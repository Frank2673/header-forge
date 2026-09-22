/**
 * 一致性校验：把线上真实的响应头与策略逐条比对
 *
 * 比对不是简单字符串相等 —— 有些头允许线上「更强」：
 *   - HSTS：max-age 更大仍算通过
 *   - CSP：多出额外指令（更严格）仍算通过
 * 否则工具会天天误报"不符"，最后没人看报告。
 *
 * @module verify
 */

import { request } from './lib/http.mjs';
import { parseHsts, parseDirectives, canonicalHeaderName } from './lib/policy.mjs';

/** 策略外仍值得关注的安全头（用于"额外发现"一节） */
const NOTABLE_HEADERS = [
  'Cross-Origin-Opener-Policy',
  'Cross-Origin-Embedder-Policy',
  'Cross-Origin-Resource-Policy',
  'X-XSS-Protection',
  'X-Permitted-Cross-Domain-Policies',
  'Server',
  'X-Powered-By',
];

/**
 * 纯函数：把实际响应头与策略比对
 * @param {object} policy
 * @param {Record<string,string>} actualHeaders 已归一小写键的响应头
 * @returns {Array<object>} 校验结果
 */
export function evaluateHeaders(policy, actualHeaders) {
  const lower = {};
  for (const [k, v] of Object.entries(actualHeaders || {})) {
    lower[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }

  const results = [];

  for (const header of Object.values(policy.headers)) {
    const key = header.name.toLowerCase();
    const actual = lower[key];

    if (actual === undefined) {
      results.push({
        name: header.name,
        status: 'missing',
        severity: header.severity,
        expected: header.value,
        actual: null,
        why: header.why,
        note: '线上未返回该响应头',
      });
      continue;
    }

    const comparison = compareHeader(header.name, header.value, actual, {
      allowStronger: header.allowStronger,
    });

    results.push({
      name: header.name,
      status: comparison.ok ? 'pass' : 'mismatch',
      severity: header.severity,
      expected: header.value,
      actual,
      why: header.why,
      note: comparison.note,
    });
  }

  /* ---- 策略外但仍存在的安全相关头 ---- */
  for (const name of NOTABLE_HEADERS) {
    const key = name.toLowerCase();
    if (lower[key] && !policy.headers[canonicalHeaderName(name)]) {
      results.push({
        name: canonicalHeaderName(name),
        status: 'extra',
        severity: 'info',
        expected: null,
        actual: lower[key],
        value: lower[key],
        note: '策略未声明该头，建议人工确认是否符合预期',
      });
    }
  }

  return results;
}

/**
 * 单个头的比对逻辑
 * @returns {{ok: boolean, note: string}}
 */
export function compareHeader(name, expected, actual, options = {}) {
  const { allowStronger = true } = options;
  const canonical = canonicalHeaderName(name);

  switch (canonical) {
    case 'Strict-Transport-Security': {
      const e = parseHsts(expected);
      const a = parseHsts(actual);
      if (a.maxAge === 0) {
        return { ok: false, note: '线上值缺少有效的 max-age' };
      }
      if (a.maxAge < e.maxAge) {
        return { ok: false, note: `max-age 偏小（线上 ${a.maxAge} < 期望 ${e.maxAge}）` };
      }
      if (e.includeSubDomains && !a.includeSubDomains) {
        return { ok: false, note: '线上值缺少 includeSubDomains' };
      }
      if (!allowStronger && a.maxAge !== e.maxAge) {
        return { ok: false, note: `max-age 与策略不等（线上 ${a.maxAge} ≠ 期望 ${e.maxAge}）` };
      }
      return { ok: true, note: 'max-age 与作用范围均满足（允许更强）' };
    }

    case 'Content-Security-Policy':
    case 'Permissions-Policy': {
      const e = parseDirectives(expected);
      const a = parseDirectives(actual);
      const missing = Object.keys(e).filter((d) => !(d in a));
      if (missing.length) {
        return { ok: false, note: `线上值缺少指令：${missing.join(', ')}` };
      }
      const weakened = Object.keys(e).filter((d) => a[d] && normalizeDirectiveValue(a[d]) !== normalizeDirectiveValue(e[d]));
      if (weakened.length) {
        return {
          ok: false,
          note: `指令取值与策略不一致：${weakened.map((d) => `${d}（线上 "${a[d]}" / 期望 "${e[d]}"）`).join('；')}`,
        };
      }
      const extraDirs = Object.keys(a).filter((d) => !(d in e));
      return {
        ok: true,
        note: extraDirs.length ? `满足策略，另有附加指令：${extraDirs.join(', ')}` : '与策略一致',
      };
    }

    case 'X-Frame-Options': {
      const ok = actual.trim().toUpperCase() === expected.trim().toUpperCase();
      return { ok, note: ok ? '一致' : `取值不同（线上 ${actual.trim()} / 期望 ${expected.trim()}）` };
    }

    default: {
      /* 其余头按忽略大小写 + 折叠空白比较 */
      const norm = (s) => String(s).trim().replace(/\s+/g, ' ').toLowerCase();
      const ok = norm(actual) === norm(expected);
      return { ok, note: ok ? '一致（忽略大小写与空白差异）' : '取值与策略不同' };
    }
  }
}

function normalizeDirectiveValue(value) {
  return String(value).trim().replace(/\s+/g, ' ');
}

/**
 * 抓取线上地址并校验
 * @param {object} policy
 * @param {string} url
 * @param {object} options
 */
export async function verifyUrl(policy, url, options = {}) {
  const startedAt = new Date().toISOString();
  const res = await request(url, { method: 'GET', timeoutMs: options.timeoutMs || 12000 });

  if (!res.ok) {
    return {
      ok: false,
      error: res.error,
      url,
      startedAt,
      results: [],
      meta: { status: null, finalUrl: url },
    };
  }

  const results = evaluateHeaders(policy, res.headers);

  return {
    ok: true,
    url,
    startedAt,
    results,
    meta: {
      status: res.status,
      finalUrl: res.finalUrl,
      redirects: res.redirects || [],
      ms: res.ms,
    },
  };
}
