/**
 * 策略模型：加载、校验、安全加固
 *
 * 「策略即代码」的关键不只是"把配置写成文件"，而是**让策略本身可被审查**：
 *   1. 结构性校验（字段、取值、头部名合法性）
 *   2. 安全基线校验（该有的头必须有，弱值必须被拒）
 *   3. 配置注入防护（值里不许出现换行等可逃逸出配置语法的字符）
 *
 * 第 3 点很重要：策略文件会被渲染进 nginx / caddy 等配置语法里，
 * 一个带换行的值就能把配置注入成任意指令。
 *
 * @module lib/policy
 */

import { readFileSync } from 'node:fs';

/** 安全基线：这些头缺失会被判为不合规 */
export const REQUIRED_HEADERS = [
  'Strict-Transport-Security',
  'Content-Security-Policy',
  'X-Content-Type-Options',
  'Referrer-Policy',
];

/** 头部名必须符合 RFC 7230 的 token 规则 */
const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** 危险字符：换行/回车/制表等会破坏生成的配置语法（注入面） */
const INJECTION_RE = /[\r\n\t\0]/;

/** 允许的严重度 */
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyError';
  }
}

/**
 * 归一化头部名：首字母大写，连字符后首字母大写（便于展示与比对）
 */
export function canonicalHeaderName(name) {
  return String(name)
    .toLowerCase()
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('-');
}

/**
 * 解析 HSTS 值
 * @returns {{maxAge: number, includeSubDomains: boolean, preload: boolean}}
 */
export function parseHsts(value) {
  const maxAgeMatch = String(value).match(/max-age\s*=\s*(\d+)/i);
  return {
    maxAge: maxAgeMatch ? Number(maxAgeMatch[1]) : 0,
    includeSubDomains: /includeSubDomains/i.test(String(value)),
    preload: /preload/i.test(String(value)),
  };
}

/** 解析「指令 值」型的结构化头部（CSP、Permissions-Policy） */
export function parseDirectives(value) {
  const out = {};
  for (const part of String(value).split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const [name, ...rest] = trimmed.split(/\s+/);
    out[name.toLowerCase()] = rest.join(' ');
  }
  return out;
}

/**
 * 加载并校验策略文件
 * @param {string} filePath
 * @returns {{version: number, targets: object, headers: object, raw: object}}
 */
export function loadPolicy(filePath) {
  let text;
  try {
    text = readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new PolicyError(`无法读取策略文件 ${filePath}：${err.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new PolicyError(`策略文件不是合法 JSON：${err.message}`);
  }

  return validatePolicy(parsed);
}

/**
 * 校验策略对象（供测试直接调用）
 */
export function validatePolicy(policy) {
  if (!policy || typeof policy !== 'object') {
    throw new PolicyError('策略必须是一个对象');
  }
  if (!policy.headers || typeof policy.headers !== 'object') {
    throw new PolicyError('策略必须包含 headers 对象');
  }

  const headerNames = Object.keys(policy.headers);
  if (headerNames.length === 0) {
    throw new PolicyError('headers 不能为空');
  }

  const normalized = {};
  const problems = [];
  /* 记录因自身有问题而被丢弃的头，避免后面再对它重复报"缺少基线头"这种误导性错误 */
  const rejected = new Set();

  for (const [name, spec] of Object.entries(policy.headers)) {
    if (!TOKEN_RE.test(name)) {
      problems.push(`头部名不合法：${name}`);
      rejected.add(canonicalHeaderName(name));
      continue;
    }
    if (!spec || typeof spec !== 'object') {
      problems.push(`${name} 的配置必须是对象`);
      rejected.add(canonicalHeaderName(name));
      continue;
    }
    if (typeof spec.value !== 'string' || spec.value.trim() === '') {
      problems.push(`${name} 缺少 value`);
      rejected.add(canonicalHeaderName(name));
      continue;
    }
    if (INJECTION_RE.test(spec.value)) {
      problems.push(
        `${name} 的 value 含换行/制表等字符 —— 会被注入进生成的配置语法，拒绝接受`
      );
      rejected.add(canonicalHeaderName(name));
      continue;
    }
    if (spec.severity && !SEVERITIES.includes(spec.severity)) {
      problems.push(`${name} 的 severity 非法：${spec.severity}`);
      rejected.add(canonicalHeaderName(name));
      continue;
    }

    normalized[canonicalHeaderName(name)] = {
      name: canonicalHeaderName(name),
      value: spec.value.trim(),
      severity: spec.severity || 'info',
      why: spec.why || '',
      /* 有些头允许线上值"更强"（如 HSTS 的 max-age 更大）也算合规 */
      allowStronger: spec.allowStronger !== false,
    };
  }

  /* ---- 安全基线 ---- */
  for (const required of REQUIRED_HEADERS) {
    if (!normalized[required] && !rejected.has(required)) {
      problems.push(`缺少安全基线要求的响应头：${required}`);
    }
  }

  if (normalized['Strict-Transport-Security']) {
    const hsts = parseHsts(normalized['Strict-Transport-Security'].value);
    if (hsts.maxAge < 15552000) {
      problems.push(
        `Strict-Transport-Security 的 max-age 过短（${hsts.maxAge} 秒），基线要求不少于 15552000 秒（180 天）`
      );
    }
    if (!hsts.includeSubDomains) {
      problems.push('Strict-Transport-Security 应包含 includeSubDomains，否则子域仍可被降级');
    }
  }

  if (normalized['Content-Security-Policy']) {
    const csp = parseDirectives(normalized['Content-Security-Policy'].value);
    if (!csp['default-src'] && !csp['script-src']) {
      problems.push('CSP 至少需要 default-src 或 script-src，否则约束力有限');
    }
    if (csp["script-src"] && /'unsafe-inline'/.test(csp['script-src'])) {
      problems.push(
        "CSP 的 script-src 含 'unsafe-inline' —— 这是 CSP 里最危险的放行，若确需请改用 nonce/hash 并在 why 中说明"
      );
    }
    if (!csp['frame-ancestors'] && !normalized['X-Frame-Options']) {
      problems.push('CSP 未声明 frame-ancestors，且没有 X-Frame-Options，点击劫持防护缺失');
    }
  }

  if (normalized['X-Frame-Options']) {
    const v = normalized['X-Frame-Options'].value.toUpperCase();
    if (v !== 'DENY' && v !== 'SAMEORIGIN') {
      problems.push(`X-Frame-Options 取值应为 DENY 或 SAMEORIGIN，当前为 ${v}`);
    }
  }

  if (normalized['X-Content-Type-Options'] && normalized['X-Content-Type-Options'].value.toLowerCase() !== 'nosniff') {
    problems.push('X-Content-Type-Options 只能是 nosniff');
  }

  if (problems.length > 0) {
    throw new PolicyError(`策略校验失败：\n   - ${problems.join('\n   - ')}`);
  }

  return {
    version: policy.version || 1,
    targets: policy.targets || {},
    headers: normalized,
    remove: Array.isArray(policy.remove) ? policy.remove : [],
    raw: policy,
  };
}

/**
 * 生成策略摘要（供报告与 CI 日志使用）
 */
export function summarizePolicy(policy) {
  const names = Object.keys(policy.headers);
  const bySeverity = {};
  for (const h of Object.values(policy.headers)) {
    bySeverity[h.severity] = (bySeverity[h.severity] || 0) + 1;
  }
  return { headerCount: names.length, names, bySeverity };
}
