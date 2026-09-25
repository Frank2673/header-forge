#!/usr/bin/env node
/**
 * Cloudflare Transform Rules（Modify Response Header）下发工具
 *
 * 为什么需要它：README 路线图里那条「支持 Cloudflare Transform Rules API 直接下发
 * （省去手工粘贴）」，真正的难点不是调 API，而是**手工粘贴这件事本身不安全**：
 *   1. 粘错一个字符，防护就静默降级，要等下一轮线上校验才发现；
 *   2. 这个 phase 的 entrypoint 里可能还有别人建的规则，一把覆盖就等于删掉它们；
 *   3. 改坏了没有退路。
 *
 * 所以本工具的三条硬规则：
 *   - **默认 dry-run**：不发任何请求，只打印将要发出的 method / URL / 请求头 / body；
 *   - **先快照再改**：apply 前必然先 GET 现有 ruleset 并存成文件，rollback 用它还原；
 *   - **令牌只从环境变量 `CLOUDFLARE_API_TOKEN` 来**：不接受命令行传参，
 *     不写进任何产物/日志/错误信息（脱敏只留前 2 位 + `***`，另给 sha256 短哈希供关联）。
 *
 * 安全边界（重要）：本模块默认 base URL 是真实 Cloudflare API。
 * 一切离线验证/测试都必须显式传 `--base-url http://127.0.0.1:<port>`；
 * 本仓库的测试与自证流程全部走本机假服务，不触达线上账号。
 *
 * 退出码：0 = 成功；1 = Cloudflare 明确拒绝（认证/权限/参数错误码）；
 *         2 = 无法完成（缺令牌、文件不存在、参数非法、连接失败、响应非 JSON）。
 *
 * @module deploy/cloudflare
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { loadPolicy, PolicyError } from '../lib/policy.mjs';

export const VERSION = '0.1.0';

/** 响应头改写所在的 phase（Cloudflare 固定取值） */
export const PHASE = 'http_response_headers_transform';
export const DEFAULT_BASE_URL = 'https://api.cloudflare.com/client/v4';

/** 本工具自建规则的描述前缀 —— 只接管带这个前缀的规则，别人的规则原样保留 */
export const MANAGED_PREFIX = 'header-forge:';

/** 快照默认落盘目录（header-forge/.gitignore 里 `tmp/` 已忽略） */
export const DEFAULT_OUT_DIR = 'tmp/cloudflare-deploy';

export const EXIT_OK = 0;
export const EXIT_REMOTE_REJECT = 1;
export const EXIT_LOCAL_ERROR = 2;

const UA = 'header-forge/0.1 (+cloudflare-transform-rules-deploy)';
const MAX_BODY_BYTES = 512 * 1024;
const SEND_TIMEOUT_MS = 15000;

/* ==================================================================== *
 * 一、令牌脱敏（沿用 surface-watch 的口径：前 2 位 + ***，另给哈希关联）
 * ==================================================================== */

/**
 * 把任意秘密值压成「前 2 位 + ***」。
 *
 * 为什么只留 2 位：留 4 位以上时，配合「长度」「字符构成」就足以在一个小搜索空间里
 * 做候选枚举（surface-watch 在 urlHash 那条上有过同类结论）。2 位 + 哈希是
 * 「人能看出自己粘错了对象」与「不构成泄露」之间的平衡点。
 */
export function redactSecret(value) {
  const s = String(value ?? '');
  if (s.length === 0) return '<空>';
  return `${s.slice(0, 2)}***`;
}

/** 脱敏后的秘密仍需一个稳定标识把「同一次配置」串起来 —— 用 sha256 前 12 位 */
export function fingerprintSecret(value) {
  return `sha256:${createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 12)}`;
}

/** 统一的展示形态：`cf*** (sha256:xxxxxxxxxxxx)` */
export function describeSecret(value) {
  return `${redactSecret(value)} (${fingerprintSecret(value)})`;
}

/**
 * 从任意文本里抹掉秘密的明文（错误信息、响应体、日志都过一遍）。
 *
 * 为什么必须做「全文替换」而不是「只在打印头时脱敏」：Cloudflare 的报错偶尔会把
 * 请求头片段回显进 error message / error_chain，一旦原样打印就等于把令牌写进 CI 日志
 * —— 而 CI 日志的可见范围往往比密钥本身大。
 *
 * 顺带抹掉「去掉空白与控制字符后」的形态：历史故障里存进去的值带过不可见字符，
 * 那种值打印出来肉眼与正常值不同，但按原文替换却匹配不到。
 */
export function scrubSecrets(text, secrets) {
  let out = String(text ?? '');
  for (const raw of secrets || []) {
    const s = String(raw ?? '');
    if (s.length < 8) continue; // 太短的值全文替换会误伤正常文本
    const variants = new Set([s, s.replace(/[^\x20-\x7e]/g, ''), s.trim()]);
    for (const v of variants) {
      if (v.length < 8) continue;
      out = out.split(v).join(redactSecret(s));
    }
  }
  return out;
}

/* ==================================================================== *
 * 二、令牌自检：本地形状体检（不发请求的那一半）
 * ==================================================================== */

/** 其它平台的凭据前缀：命中即判定为「粘错了对象」，硬阻断 */
const OTHER_PLATFORM_PREFIXES = [
  ['ghp_', 'GitHub Personal Access Token'],
  ['github_pat_', 'GitHub fine-grained PAT'],
  ['glpat-', 'GitLab Personal Access Token'],
  ['AKIA', 'AWS Access Key ID'],
  ['xoxb-', 'Slack Bot Token'],
  ['AIza', 'Google API Key'],
  ['sk-', 'OpenAI 风格 API Key'],
];

/**
 * 令牌体检（**绝不在返回值里带上令牌原文**）
 *
 * 设计立场来自本项目踩过的两个坑：
 *   - 只做「40 位字母数字」格式判断 → 新格式（cfut_/cfat_/cfk_ 前缀）被误判为格式错误；
 *   - 反过来把格式判断当门禁 → 格式假设一旦过时，有效令牌又被拦下。
 * 所以这里把问题分成两类：
 *   - **blocking**：非可打印字符 / 空白 / 明显是网址或命令文本 / 其它平台凭据
 *     —— 这些「不可能是 HTTP 头里的凭据」，一定是配置错误，本地就拦下，别浪费一轮 CI；
 *   - **warning**：格式不认识 —— 只告警，最终判定权交给 Cloudflare API。
 *
 * @returns {{
 *   present: boolean, ok: boolean, format: string,
 *   length: number, redacted: string, fingerprint: string,
 *   counts: {upper:number, lower:number, digit:number, hyphen:number, underscore:number, other:number},
 *   spaces: number, nonPrintableHex: string[], markers: string[],
 *   blocking: string[], warnings: string[]
 * }}
 */
export function inspectToken(raw) {
  const value = String(raw ?? '');
  const counts = { upper: 0, lower: 0, digit: 0, hyphen: 0, underscore: 0, other: 0 };
  const nonPrintableHex = [];
  let spaces = 0;

  for (const ch of value) {
    const cp = ch.codePointAt(0);
    if (cp >= 0x41 && cp <= 0x5a) counts.upper++;
    else if (cp >= 0x61 && cp <= 0x7a) counts.lower++;
    else if (cp >= 0x30 && cp <= 0x39) counts.digit++;
    else if (ch === '-') counts.hyphen++;
    else if (ch === '_') counts.underscore++;
    else counts.other++;

    if (cp === 0x20) spaces++;
    else if (cp < 0x20 || cp > 0x7e) {
      nonPrintableHex.push(`U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
    }
  }

  const blocking = [];
  const warnings = [];
  const markers = [];

  if (value.length === 0) {
    return {
      present: false,
      ok: false,
      format: 'absent',
      length: 0,
      redacted: '<空>',
      fingerprint: fingerprintSecret(''),
      counts,
      spaces: 0,
      nonPrintableHex: [],
      markers: [],
      blocking: ['未设置 CLOUDFLARE_API_TOKEN'],
      warnings: [],
    };
  }

  /* ---- 阻断类：不可能构成合法 Authorization 头 ---- */
  if (nonPrintableHex.length) {
    blocking.push(
      `值里有 ${nonPrintableHex.length} 个不可打印/非 ASCII 字符（${nonPrintableHex.join(', ')}）` +
        ' —— 会让 Authorization 头格式非法（历史故障：CI 返回 6003 / 6111）'
    );
  }
  if (spaces > 0) {
    blocking.push(`值里有 ${spaces} 个空格 —— HTTP 头里 Bearer 令牌不能含空格`);
  }
  for (const [prefix, label] of OTHER_PLATFORM_PREFIXES) {
    if (value.startsWith(prefix)) {
      blocking.push(`值以 ${prefix} 开头，看起来是 ${label}，不是 Cloudflare 凭据`);
      break;
    }
  }

  /* ---- 阻断类：粘成了网址 / 命令文本（本项目历史上真实发生过两次） ---- */
  if (/^https?:\/\//i.test(value)) {
    markers.push('以 http(s):// 开头');
    blocking.push('值以 http(s):// 开头 —— 像是把 API 网址复制进来了，应改成控制台的 Copy 按钮复制令牌值');
  } else if (/:\/\//.test(value)) {
    markers.push('含 ://');
    blocking.push('值里含 :// —— 像是一段网址（历史故障：密钥里存过 curl 命令与网址文本）');
  }
  if (/^(curl|wget|export|set|Invoke-|node|python|npm)\b/i.test(value)) {
    markers.push('以命令名开头');
    blocking.push('值以命令名开头 —— 粘进来的是命令文本，不是令牌值');
  }
  if (/^Bearer\s/i.test(value)) {
    markers.push('含 Bearer 前缀');
    blocking.push('值本身带了 "Bearer " 前缀 —— 本工具会自己加，重复会导致 6111');
  }

  /* ---- 格式识别（仅告警，不做门禁） ---- */
  /* 前缀形状来自本项目的历史记录（tmp/commit-msg2.txt）：cfut_ 用户级 / cfat_ 账户级 / cfk_ Global API Key */
  let format = 'unknown';
  if (/^cf(?:ut|at|k)_[A-Za-z0-9_-]{20,}$/.test(value)) format = 'scannable';
  else if (/^[A-Za-z0-9_-]{40}$/.test(value)) format = 'legacy';
  else {
    warnings.push(
      '格式不在已知的两种之内（cfut_/cfat_/cfk_ 带前缀格式、或 40 位旧格式）——' +
        ' 按历史教训不在这里阻断，令牌是否有效以 --verify-token 的 API 结果为准'
    );
  }

  return {
    present: true,
    ok: blocking.length === 0,
    format,
    length: value.length,
    redacted: redactSecret(value),
    fingerprint: fingerprintSecret(value),
    counts,
    spaces,
    nonPrintableHex,
    markers,
    blocking,
    warnings,
  };
}

/* ==================================================================== *
 * 三、策略 → Cloudflare 规则体
 * ==================================================================== */

/**
 * 把策略渲染成 Modify Response Header 规则。
 *
 * 分两条规则而不是「一个头一条」：Cloudflare 每个 phase 的规则条数有配额，
 * 7 个头一条一条上很快就顶到上限；而 `action_parameters.headers` 本身是映射，
 * 一次可以带多条 set / remove。规则描述带 `header-forge:` 前缀，
 * 这是「本工具的规则」与「别人的规则」的唯一判据（回滚与合并都靠它）。
 *
 * @param {object} policy loadPolicy 的返回值
 * @param {{expression?: string}} [options] expression 默认 `true`（对该 zone 所有请求生效）
 * @returns {Array<object>} 规则数组（顺序确定：先 set 后 remove）
 */
export function buildRulesetRules(policy, options = {}) {
  const expression = options.expression || 'true';
  const setHeaders = {};
  const removeHeaders = {};

  for (const [name, spec] of Object.entries(policy.headers || {})) {
    setHeaders[name] = { operation: 'set', value: spec.value };
  }
  for (const name of policy.remove || []) {
    removeHeaders[String(name)] = { operation: 'remove' };
  }

  const rules = [];
  if (Object.keys(setHeaders).length) {
    rules.push({
      description: `${MANAGED_PREFIX}set-response-headers`,
      expression,
      action: 'rewrite',
      action_parameters: { headers: setHeaders },
    });
  }
  if (Object.keys(removeHeaders).length) {
    rules.push({
      description: `${MANAGED_PREFIX}remove-response-headers`,
      expression,
      action: 'rewrite',
      action_parameters: { headers: removeHeaders },
    });
  }
  return rules;
}

export function isManagedRule(rule) {
  return String(rule?.description || '').startsWith(MANAGED_PREFIX);
}

/**
 * 合并：**只替换本工具的规则，别人的规则原样保留**。
 *
 * 这一步是整个工具里最要紧的安全属性。这个 phase 的 entrypoint 是整段配置，
 * PUT 是全量覆盖语义 —— 直接把我们生成的 rules 发上去，等于删掉别人建的规则，
 * 而且删的时候不会有任何提示。Cloudflare 控制台里手工改拦不住这件事，
 * 只能在工具侧保证。
 *
 * 顺序：别人的规则在前、本工具的在后（同名头时后写的生效 —— 本工具是策略的
 * 唯一事实来源，所以它应该赢）。
 */
export function planMerge(existingRules, managedRules) {
  const all = Array.isArray(existingRules) ? existingRules : [];
  const foreign = all.filter((r) => !isManagedRule(r));
  const replaced = all.filter((r) => isManagedRule(r));
  return {
    rules: [...foreign, ...managedRules],
    keptForeign: foreign.length,
    replacedManaged: replaced.length,
  };
}

/* ==================================================================== *
 * 四、API 失败诊断
 * ==================================================================== */

/** 把 Cloudflare 的错误体摊平成 code/message 列表（含 error_chain） */
export function flattenErrors(errors) {
  const out = [];
  for (const e of Array.isArray(errors) ? errors : []) {
    if (!e || typeof e !== 'object') continue;
    out.push({ code: e.code, message: String(e.message ?? '') });
    for (const c of flattenErrors(e.error_chain)) out.push(c);
  }
  return out;
}

/**
 * 从响应体里收集错误。
 *
 * 要处理两种形态：新的 `{success:false, errors:[...]}`，
 * 以及**旧的顶层形态** —— 本项目历史上真收到过
 * `{"code":6003,"message":"Invalid request headers","error_chain":[{"code":6111,...}]}`
 * （见 tmp/commit-msg4.txt）。只认 `errors` 数组的话，6111 会被误判成
 * 「400 参数错误」，把「值里有脏字符」这个真因藏起来。
 */
export function collectApiErrors(parsed) {
  if (!parsed || typeof parsed !== 'object') return [];
  if (Array.isArray(parsed.errors) && parsed.errors.length) return parsed.errors;
  if (typeof parsed.code === 'number') {
    return [{ code: parsed.code, message: parsed.message, error_chain: parsed.error_chain }];
  }
  return [];
}

/**
 * 错误码 → 可执行诊断。
 *
 * 这张表只做一件事：把「Cloudflare 说不」翻译成「你现在该去改什么」。
 * 每一行的来源都标在 docs/cloudflare-deploy.md 的对照表里（哪些是本项目实测观察、
 * 哪些是文档知识），不在这里假装全部验证过。
 */
export function diagnoseApiFailure(status, errors) {
  const flat = flattenErrors(errors);
  const codes = flat.map((e) => e.code);
  const has = (...c) => c.some((x) => codes.includes(x));

  if (status === 401 || has(10000)) {
    return {
      level: 'auth',
      hint:
        '认证失败：令牌无效、已被吊销，或压根没送到。先跑 --verify-token；' +
        '再用 docs/cloudflare-deploy.md 的「令牌自检清单」逐项核对。',
    };
  }
  if (status === 403) {
    return {
      level: 'permission',
      hint:
        '权限不足：令牌有效但没有这个 zone / 这个接口的权限。' +
        'Transform Rules 下发至少要 Zone Read + Transform Rules Edit，' +
        '且 Zone Resources 必须包含目标 zone（见 docs/cloudflare-deploy.md 的权限范围一节）。',
    };
  }
  if (has(6111, 6003)) {
    return {
      level: 'header-format',
      hint:
        'Authorization 头格式非法 —— 不是「令牌无效」，而是「值里有东西」。' +
        '最常见两类：① 值里带不可见字符（零宽空格 / BOM / 全角）；' +
        '② 值根本不是令牌，而是一段网址或命令文本。用 --verify-token 的构成指纹定位。',
    };
  }
  if (has(9106, 9103, 9107, 9109)) {
    return {
      level: 'legacy-auth',
      hint:
        '认证头缺失或走了旧式鉴权路径：确认只用了 Authorization: Bearer <token>，' +
        '没有同时带 X-Auth-Email / X-Auth-Key；并确认代理没有把 Authorization 头吃掉。',
    };
  }
  if (has(7003, 7000)) {
    return { level: 'not-found', hint: '目标 zone / ruleset 不存在或 zone id 不对 —— 先确认 --zone 指向的 zone。' };
  }
  if (status === 400) {
    return { level: 'bad-request', hint: '请求体被拒：对照上面返回的原始响应体检查 rules 结构（action / expression / action_parameters）。' };
  }
  if (status === 429) {
    return { level: 'rate-limit', hint: '触发限流：等一会儿再试，或减小下发频率。' };
  }
  if (status >= 500) {
    return { level: 'server', hint: 'Cloudflare 侧错误：先确认线上是否已经被改（GET 一次 entrypoint），再决定是否重试。' };
  }
  return { level: 'unknown', hint: '未归类的失败：以上原始响应体为准，不要凭猜测重试。' };
}

/* ==================================================================== *
 * 五、HTTP（零依赖，可注入 base URL）
 * ==================================================================== */

function sendOnce({ method, url, headers, body, timeoutMs = SEND_TIMEOUT_MS }) {
  return new Promise((resolvePromise) => {
    const parsed = new URL(url);
    const client = parsed.protocol === 'http:' ? http : https;
    const payload = body === undefined || body === null ? null : Buffer.from(JSON.stringify(body), 'utf8');

    const req = client.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          'User-Agent': UA,
          Accept: 'application/json',
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
          ...headers,
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        let received = 0;
        let sawEnd = false;
        let settled = false;

        const finish = () => {
          if (settled) return;
          settled = true;
          resolvePromise({
            ok: true,
            status: res.statusCode,
            headers: res.headers,
            bodyText: Buffer.concat(chunks).toString('utf8'),
            truncated: received > MAX_BODY_BYTES,
          });
        };

        res.on('data', (chunk) => {
          received += chunk.length;
          if (received <= MAX_BODY_BYTES) chunks.push(chunk);
          else res.destroy();
        });
        res.on('end', () => {
          sawEnd = true;
          finish();
        });
        /* 沿用 lib/http.mjs 的教训：残缺响应必须判失败，否则会拿半截 JSON 当结果 */
        res.on('close', () => {
          if (settled) return;
          if (sawEnd) return finish();
          settled = true;
          resolvePromise({ ok: false, error: 'INCOMPLETE_RESPONSE' });
        });
      }
    );

    req.on('timeout', () => req.destroy(Object.assign(new Error('请求超时'), { code: 'TIMEOUT' })));
    req.on('error', (err) => resolvePromise({ ok: false, error: err.code || err.message }));
    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * 发一个请求。永不抛异常；网络问题变成 `{ok:false, error}`。
 * GET 允许 1 次重试；PUT **不重试**（写操作的一次静默重放比一次失败更贵）。
 */
async function send(request, { attempts = 1, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  let last = null;
  for (let i = 0; i < attempts; i++) {
    last = await sendOnce(request);
    if (last.ok) return last;
    if (i + 1 < attempts) await sleep(300);
  }
  return last;
}

/* ==================================================================== *
 * 六、请求计划（dry-run 的全部内容都来自这里）
 * ==================================================================== */

function entrypointPath(zoneRef) {
  return `/zones/${zoneRef}/rulesets/phases/${PHASE}/entrypoint`;
}

function isZoneId(value) {
  return /^[0-9a-f]{32}$/i.test(String(value || ''));
}

/**
 * 计划将要发出的请求。
 *
 * @param {object} o
 * @param {string} o.baseUrl
 * @param {string} o.zone zone id（32 位十六进制）或 zone 名
 * @param {Array<object>} [o.managedRules]
 * @param {Array<object>} [o.existingRules] 已捕获的现有规则（dry-run 时来自快照，apply 时来自 GET）
 * @param {boolean} [o.knownExisting] existingRules 是否为已知（决定 body 是否已合并）
 * @returns {Array<{n:number, method:string, url:string, summary:string, body?:object}>}
 */
export function buildDeployPlan({ baseUrl, zone, managedRules = [], existingRules = null, knownExisting = false }) {
  const plan = [];
  const zoneId = isZoneId(zone) ? String(zone) : '<zone-id>';

  if (!isZoneId(zone)) {
    plan.push({
      n: plan.length + 1,
      method: 'GET',
      url: `${baseUrl}/zones?name=${encodeURIComponent(zone)}`,
      summary: '按名字解析 zone（拿到 zone id 才能拼后面的路径）',
    });
  }

  plan.push({
    n: plan.length + 1,
    method: 'GET',
    url: `${baseUrl}${entrypointPath(zoneId)}`,
    summary: '读现有 ruleset —— 这一步的响应会先落成快照（cf-ruleset-before-<ts>.json），再去改',
  });

  const merge = knownExisting ? planMerge(existingRules, managedRules) : null;
  plan.push({
    n: plan.length + 1,
    method: 'PUT',
    url: `${baseUrl}${entrypointPath(zoneId)}`,
    summary: merge
      ? `全量覆盖 entrypoint：保留别人的规则 ${merge.keptForeign} 条、替换本工具规则 ${merge.replacedManaged} 条、写入 ${managedRules.length} 条`
      : '全量覆盖 entrypoint：实际 body = 服务端现有规则里**非本工具**的部分 + 下面的规则（要 GET 之后才知道前者是什么）',
    body: { rules: merge ? merge.rules : managedRules },
  });

  return plan;
}

/* ==================================================================== *
 * 七、快照
 * ==================================================================== */

/** 快照文件名（时间戳进名字，绝不覆盖旧快照） */
export function snapshotFileName(date = new Date()) {
  const ts = date.toISOString().replace(/[:.]/g, '-');
  return `cf-ruleset-before-${ts}.json`;
}

export function buildSnapshot({ baseUrl, zone, entrypoint, at = new Date(), source = 'GET entrypoint' }) {
  return {
    tool: `header-forge v${VERSION}`,
    kind: 'cloudflare-transform-rules-snapshot',
    createdAt: at.toISOString(),
    source,
    baseUrl,
    zone,
    phase: PHASE,
    /* 原样保存 API 返回的 result —— 回滚就是把它原样 PUT 回去，不做任何「理解」 */
    entrypoint,
  };
}

/* ==================================================================== *
 * 八、CLI
 * ==================================================================== */

const TAKES_VALUE = new Set([
  '--policy', '--zone', '--out', '--base-url', '--rollback', '--expression', '--from-snapshot',
]);

export function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (TAKES_VALUE.has(token)) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) throw new Error(`${token} 需要一个值`);
      args[token.slice(2)] = value;
      i++;
    } else if (token.startsWith('--')) {
      args[token.slice(2)] = true;
    } else {
      args._.push(token);
    }
  }
  return args;
}

const HELP = `
header-forge cloudflare —— 把 headers.policy.json 下发成 Cloudflare Transform Rules（默认 dry-run）

用法：node src/deploy/cloudflare.mjs --zone <zone-id|zone名> [--apply] [选项]

模式（默认 dry-run，什么都不发）：
  --dry-run                打印将要发出的每个请求（method / URL / 头概要 / body JSON），不发请求
  --apply                  真的下发：先 GET 现有 ruleset 存快照 → 再 PUT 覆盖
  --rollback <快照文件>    用快照还原；不加 --apply 时只打印将要 PUT 的 body
  --verify-token           调 GET /user/tokens/verify 自检令牌是否有效

选项：
  --policy <路径>          策略文件（默认 headers.policy.json）
  --zone <zone-id|名字>    目标 zone：32 位 hex 视为 id，否则先按名字解析
  --out <目录>             快照目录（默认 ${DEFAULT_OUT_DIR}）
  --base-url <URL>         API 基址（默认 ${DEFAULT_BASE_URL}）
                           离线测试请传 --base-url http://127.0.0.1:<port>
  --expression <表达式>    规则生效条件（默认 true = 整个 zone）
  --from-snapshot <文件>   dry-run 时用快照里的现有规则预演合并结果（让预览与 apply 完全一致）

令牌：只从环境变量 CLOUDFLARE_API_TOKEN 读取。**不支持命令行传参**，
      也不会写进任何产物、日志或错误信息（只输出前 2 位 + sha256 短哈希）。

退出码：0 成功 / 1 Cloudflare 明确拒绝（认证、权限、参数错误码）/ 2 无法完成（缺令牌、文件、参数、连接失败）
`.trim();

/**
 * CLI 主流程（导出以便测试在进程内直接调用 —— 本机沙箱禁子进程管道，
 * 测试不能 spawn 一个 CLI 再读它的 stdout）。
 *
 * @param {string[]} argv 不含 node 与脚本路径
 * @param {{env?: object, cwd?: string, log?: Function, errLog?: Function, now?: () => Date}} [io]
 * @returns {Promise<number>} 退出码
 */
export async function runDeploy(argv, io = {}) {
  const env = io.env || process.env;
  const cwd = io.cwd || process.cwd();
  const log = io.log || ((...a) => console.log(...a));
  const errLog = io.errLog || ((...a) => console.error(...a));
  const now = io.now || (() => new Date());

  const args = parseArgs(argv);
  if (args.help || args.h) {
    log(HELP);
    return EXIT_OK;
  }
  if (args['dry-run'] && args.apply) {
    errLog('🛑 --dry-run 与 --apply 互斥：要么预览，要么真发。');
    return EXIT_LOCAL_ERROR;
  }

  const policyPath = args.policy || 'headers.policy.json';
  const outDir = args.out || DEFAULT_OUT_DIR;
  const baseUrl = String(args['base-url'] || env.CLOUDFLARE_API_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, '');
  const apply = Boolean(args.apply);

  const rawToken = env.CLOUDFLARE_API_TOKEN;
  const token = rawToken == null ? '' : String(rawToken);
  /* 全文脱敏的字典：错误信息、响应体、以及「去掉控制字符后的形态」都抹一遍 */
  const secrets = token ? [token, token.replace(/[^\x20-\x7e]/g, '')] : [];
  const shape = inspectToken(token);
  const verbose = 'verbose' in args;

  const head = (mode) =>
    log(`\n☁️  header-forge cloudflare · ${mode} · ${apply ? 'APPLY（会真的改线上）' : 'DRY-RUN（不发任何请求）'}`);

  const printTokenLine = () => {
    if (shape.present) log(`  令牌：${describeSecret(token)} · 长度 ${shape.length} · 格式 ${shape.format}`);
    else log('  令牌：<未设置 CLOUDFLARE_API_TOKEN>');
  };

  const printShapeReport = () => {
    if (!shape.present) return;
    const c = shape.counts;
    log(
      `  构成指纹：大写 ${c.upper}｜小写 ${c.lower}｜数字 ${c.digit}｜连字符 ${c.hyphen}｜` +
        `下划线 ${c.underscore}｜其它 ${c.other}`
    );
    for (const m of shape.markers) log(`  ⚠️ 可疑形态：${m}`);
    for (const b of shape.blocking) errLog(`  🛑 ${b}`);
    for (const w of shape.warnings) log(`  ℹ️ ${w}`);
  };

  /* ---------------- 未设置令牌 ---------------- */
  if (!shape.present) {
    if (args['verify-token'] || apply) {
      head(args['verify-token'] ? '令牌自检' : '下发');
      errLog('\n🛑 未设置 CLOUDFLARE_API_TOKEN —— ');
      errLog('   本工具**只**从环境变量读令牌，不接受命令行传参（命令行会进 shell 历史与进程列表）。');
      errLog('   PowerShell：$env:CLOUDFLARE_API_TOKEN = "..."（仅当前会话）');
      errLog('   bash/zsh  ：export CLOUDFLARE_API_TOKEN="..."');
      errLog('   取令牌：Cloudflare 控制台 → My Profile → API Tokens → Create Token（用 Copy 按钮复制值，别复制页面文本）。');
      errLog('   ⚠️ 未做任何改动：没有发出任何请求。');
      return EXIT_LOCAL_ERROR;
    }
  }

  /* ---------------- 令牌形态阻断：本地拦下，浪费一轮 CI 的成本比这高 ---------------- */
  if (shape.present && !shape.ok) {
    head(args['verify-token'] ? '令牌自检' : args.rollback ? '回滚' : '下发');
    printTokenLine();
    printShapeReport();
    errLog('\n🛑 令牌值本身不可能是合法的 Authorization 头 —— 已停止，未发出任何请求。');
    errLog('   这类错误在本项目历史上真实发生过（存进去的是一段 curl 命令 / 带不可见字符的值）。');
    errLog('   处置：用控制台的 Copy 按钮重新复制令牌，再写回环境变量。详见 docs/cloudflare-deploy.md。');
    return EXIT_LOCAL_ERROR;
  }

  const authHeader = shape.present ? { Authorization: `Bearer ${token}` } : {};
  const headerSummary = shape.present
    ? `Authorization: Bearer ${describeSecret(token)} · Content-Type: application/json`
    : 'Authorization: <未设置令牌> · Content-Type: application/json';

  const renderRequest = (req) => {
    log(`\n  [${req.n}] ${req.method} ${req.url}`);
    log(`      ${req.summary}`);
    log(`      请求头：${headerSummary}`);
    if (req.body === undefined) log('      请求体：无');
    else log(`      请求体：\n${JSON.stringify(req.body, null, 2).split('\n').map((l) => '      ' + l).join('\n')}`);
  };

  /** 统一的响应处理：打印状态与（脱敏后的）原始响应体 */
  const handleResponse = (label, res) => {
    if (!res.ok) {
      errLog(`\n🛑 ${label}：请求没能完成（${res.error}）—— 这**不等于**线上没改。`);
      errLog('   连接断开时 Cloudflare 可能已经处理了请求，处置顺序：先 GET entrypoint 看现状，再决定重试或回滚。');
      return EXIT_LOCAL_ERROR;
    }
    let parsed = null;
    try {
      parsed = JSON.parse(res.bodyText);
    } catch {
      /* 非 JSON 也照样打印（脱敏后），但不猜它是什么意思 */
    }
    log(`\n  ← ${label}：HTTP ${res.status}${parsed?.success === true ? ' · success=true' : ''}`);
    log(`    原始响应体（脱敏后）：${scrubSecrets(res.bodyText, secrets).slice(0, 4000)}`);
    if (verbose) log(`    响应头：${JSON.stringify(res.headers)}`);

    if (parsed && (res.status >= 400 || parsed.success === false)) {
      const d = diagnoseApiFailure(res.status, collectApiErrors(parsed));
      errLog(`\n🛑 Cloudflare 拒绝（${d.level}）：${d.hint}`);
      return EXIT_REMOTE_REJECT;
    }
    if (res.status >= 400) {
      const d = diagnoseApiFailure(res.status, []);
      errLog(`\n🛑 HTTP ${res.status}（${d.level}）：${d.hint}`);
      return EXIT_REMOTE_REJECT;
    }
    return EXIT_OK;
  };

  /* ============================ verify-token ============================ */
  if (args['verify-token']) {
    head('令牌自检');
    printTokenLine();
    printShapeReport();
    const req = { n: 1, method: 'GET', url: `${baseUrl}/user/tokens/verify`, summary: '自检令牌是否有效（这个接口不校验业务权限）' };
    log('\n将要发出的请求：');
    renderRequest(req);
    const res = await send({ method: 'GET', url: req.url, headers: authHeader }, { attempts: 2 });
    const code = handleResponse('令牌自检', res);
    if (code === EXIT_OK) {
      log('\n✅ 令牌有效（status=active）。');
      log('   ⚠️ 但这一条**不能**证明它能下发 Transform Rules —— /user/tokens/verify 只看令牌本身，');
      log('      不看权限范围。真正的权限判定在下发那一步（403 = 权限不足，见 docs/cloudflare-deploy.md）。');
    }
    return code;
  }

  /* ============================== rollback ============================== */
  if (args.rollback) {
    const snapPath = resolve(cwd, String(args.rollback));
    head('回滚');
    printTokenLine();
    printShapeReport();

    if (!existsSync(snapPath)) {
      errLog(`\n🛑 快照文件不存在：${snapPath}`);
      return EXIT_LOCAL_ERROR;
    }
    let snap;
    try {
      snap = JSON.parse(readFileSync(snapPath, 'utf8'));
    } catch (err) {
      errLog(`\n🛑 快照不是合法 JSON：${err.message}`);
      return EXIT_LOCAL_ERROR;
    }
    const snapRules = snap?.entrypoint?.rules;
    if (!Array.isArray(snapRules)) {
      errLog('\n🛑 快照里没有 entrypoint.rules —— 不是本工具写出的快照，拒绝用它回滚。');
      return EXIT_LOCAL_ERROR;
    }
    const zoneArg = args.zone || snap?.zone?.id || snap?.zone?.name;
    if (!zoneArg) {
      errLog('\n🛑 快照里没有 zone，也没给 --zone，无法拼出还原路径。');
      return EXIT_LOCAL_ERROR;
    }
    if (args.zone && snap?.zone?.id && isZoneId(args.zone) && String(args.zone) !== String(snap.zone.id)) {
      errLog('\n🛑 --zone 与快照里的 zone id 不一致 —— 拒绝把 A 区的配置还原到 B 区。');
      errLog(`   --zone=${args.zone}；快照 zone=${String(snap.zone.id)}`);
      return EXIT_LOCAL_ERROR;
    }

    log(`  快照：${snapPath}`);
    log(`  快照时间：${snap.createdAt} · zone=${snap?.zone?.name || snap?.zone?.id || '?'} · ${snapRules.length} 条规则`);

    const managedSnap = snapRules.filter(isManagedRule).length;
    const plan = [{
      n: 1,
      method: 'PUT',
      url: `${baseUrl}${entrypointPath(isZoneId(zoneArg) ? zoneArg : '<zone-id>')}`,
      summary: `还原为快照状态：${snapRules.length} 条规则（其中本工具规则 ${managedSnap} 条，别人的规则 ${snapRules.length - managedSnap} 条）`,
      body: { rules: snapRules },
    }];

    log('\n将要发出的请求：');
    plan.forEach(renderRequest);

    if (!apply) {
      log('\n🧪 DRY-RUN：以上请求**没有发出**。确认无误后加 --apply 执行回滚。');
      return EXIT_OK;
    }

    /* 回滚前先 GET 一次：既确认路径可达，也把「回滚前」的状态留在输出里 */
    log('\n已确认 --apply，开始执行回滚：');
    errLog('  ⚠️ 回滚会把 entrypoint 恢复成快照那一刻的状态 —— 快照之后别人做的改动也会被一并抹掉。');
    const res = await send({ method: 'PUT', url: plan[0].url, headers: authHeader, body: plan[0].body });
    const code = handleResponse('回滚', res);
    if (code === EXIT_OK) log('\n✅ 已还原为快照状态。建议立刻跑一次线上校验（verify）确认响应头回到预期。');
    return code;
  }

  /* =============================== 下发 =============================== */
  if (!args.zone) {
    head('下发');
    errLog('\n🛑 需要 --zone <zone-id|zone名>。');
    errLog('   取 zone id：Cloudflare 控制台 → 选中域名 → Overview 右下角 Account ID 下方即是 Zone ID；');
    errLog('   或直接给域名（本工具会调 GET /zones?name=<域名> 解析，这一步放在 dry-run 里也能看到）。');
    return EXIT_LOCAL_ERROR;
  }

  let policy;
  try {
    policy = loadPolicy(resolve(cwd, policyPath));
  } catch (err) {
    head('下发');
    if (err instanceof PolicyError) {
      errLog(`\n🛑 策略校验失败：\n${err.message}`);
      errLog('   策略会被下发进线上配置，所以必须先过全部基线检查。');
    } else {
      errLog(`\n🛑 读取策略失败：${err.message}`);
    }
    return EXIT_LOCAL_ERROR;
  }

  const managedRules = buildRulesetRules(policy, { expression: args.expression });
  const setCount = Object.keys(policy.headers).length;
  const removeCount = (policy.remove || []).length;

  head('下发');
  log(`  策略：${policyPath} —— ${setCount} 个头 set、${removeCount} 个头 remove → ${managedRules.length} 条 Cloudflare 规则`);
  log(`  目标：${baseUrl} · zone=${args.zone} · phase=${PHASE}`);
  printTokenLine();
  printShapeReport();

  if (!shape.present) {
    log('\n  ℹ️ 未设置 CLOUDFLARE_API_TOKEN：dry-run 照常预览，但 --apply 会被安全拦下。');
  }

  /* dry-run 的合并预览：有 --from-snapshot 才能算出「保留别人的几条」 */
  let existingRules = null;
  let knownExisting = false;
  if (args['from-snapshot']) {
    const p = resolve(cwd, String(args['from-snapshot']));
    try {
      const snap = JSON.parse(readFileSync(p, 'utf8'));
      existingRules = snap?.entrypoint?.rules ?? [];
      knownExisting = true;
      log(`  现有规则来自快照预览：${p}（${existingRules.length} 条）`);
    } catch (err) {
      errLog(`\n🛑 --from-snapshot 读取失败：${err.message}`);
      return EXIT_LOCAL_ERROR;
    }
  }

  if (!apply) {
    const plan = buildDeployPlan({
      baseUrl,
      zone: args.zone,
      managedRules,
      existingRules,
      knownExisting,
    });
    log('\n将要发出的请求（**顺序不可调换**：先解析 zone，再读现状，最后才覆盖）：');
    plan.forEach(renderRequest);
    log('\n🧪 DRY-RUN 结束：以上请求**一个都没有发出**（假服务侧请求记录应为 0 行）。');
    log('   确认无误后加 --apply 执行；下发前本工具会先 GET 现有 ruleset 存快照。');
    if (!knownExisting) {
      log('   提示：想看到与 apply 完全一致的 PUT body（含「保留别人的规则 N 条」），');
      log('         先跑一次 apply 拿到的快照，再用 --from-snapshot <快照> --dry-run 预演。');
    }
    return EXIT_OK;
  }

  /* ------------------------------ apply ------------------------------ */
  errLog('\n⚠️ 已确认 --apply：接下来会**真实修改线上配置**。');
  let zoneRef = args.zone;
  if (!isZoneId(zoneRef)) {
    const url = `${baseUrl}/zones?name=${encodeURIComponent(zoneRef)}`;
    log(`\n  [1] GET ${url}\n      按名字解析 zone…`);
    const res = await send({ method: 'GET', url, headers: authHeader }, { attempts: 2 });
    const code = handleResponse('解析 zone', res);
    if (code !== EXIT_OK) return code;
    let parsed;
    try {
      parsed = JSON.parse(res.bodyText);
    } catch {
      errLog('\n🛑 解析 zone 的响应不是 JSON，无法继续。');
      return EXIT_LOCAL_ERROR;
    }
    const first = Array.isArray(parsed.result) ? parsed.result[0] : null;
    if (!first?.id) {
      errLog(`\n🛑 没找到名为 ${zoneRef} 的 zone（或令牌没有 Zone Read 权限，列表为空）。`);
      errLog('   权限不足时这个接口会返回空列表而不是 403 —— 这是最容易误判的一种失败。');
      return EXIT_LOCAL_ERROR;
    }
    zoneRef = first.id;
    log(`      → zone id = ${zoneRef}（${first.name}）`);
  }

  const epUrl = `${baseUrl}${entrypointPath(zoneRef)}`;

  /* ① 快照：任何写操作之前，先把现状存下来 */
  const stamp = now();
  log(`\n  [2] GET ${epUrl}\n      读取现有 ruleset（这一步的响应会先落盘成快照）…`);
  const before = await send({ method: 'GET', url: epUrl, headers: authHeader }, { attempts: 2 });
  let beforeParsed = null;
  if (before.ok) {
    try {
      beforeParsed = JSON.parse(before.bodyText);
    } catch {
      beforeParsed = null;
    }
  }

  /* 404 的处置与其它失败不同：不是「被拒绝」，而是「这个 zone 还没建过这个 phase 的 ruleset」 */
  if (before.ok && before.status === 404) {
    errLog('\n🛑 这个 zone 还没有 http_response_headers_transform 的 entrypoint ruleset。');
    errLog('   本工具当前不去「创建」ruleset（创建是不可预知的一步，且控制台里点一下就有了）。');
    errLog('   处置：先在 Cloudflare 控制台 → Rules → Transform Rules → Modify Response Header 建一条任意规则，');
    errLog('   再回来跑本工具 —— 它会读出现状、存快照、然后覆盖成策略要求的样子。');
    return EXIT_LOCAL_ERROR;
  }
  if (before.ok && beforeParsed?.success === false && flattenErrors(beforeParsed.errors).some((e) => [7003, 7000].includes(e.code))) {
    errLog('\n🛑 Cloudflare 说这个 ruleset 不存在（7003/7000）—— 同上：先在控制台建一条任意规则再来跑。');
    return EXIT_LOCAL_ERROR;
  }

  const beforeCode = handleResponse('读取现有 ruleset', before);
  if (beforeCode !== EXIT_OK) {
    errLog('\n🛑 读不到现状就不动手 —— 没有快照的一次覆盖是不可回滚的。');
    return beforeCode;
  }
  if (!beforeParsed) {
    errLog('\n🛑 现有 ruleset 的响应不是 JSON，拒绝在没有快照的前提下继续。');
    return EXIT_LOCAL_ERROR;
  }

  const entrypoint = beforeParsed.result ?? {};
  const currentRules = Array.isArray(entrypoint.rules) ? entrypoint.rules : [];
  const snapshot = buildSnapshot({
    baseUrl,
    zone: { id: zoneRef, name: entrypoint?.zone_name || (isZoneId(args.zone) ? undefined : args.zone) },
    entrypoint,
    at: stamp,
  });

  const outAbs = resolve(cwd, outDir);
  mkdirSync(outAbs, { recursive: true });
  const snapPath = join(outAbs, snapshotFileName(stamp));
  writeFileSync(snapPath, JSON.stringify(snapshot, null, 2) + '\n', 'utf8');
  const snapText = readFileSync(snapPath, 'utf8');
  log(`\n  📸 变更前快照：${snapPath}`);
  log(`     ${currentRules.length} 条规则已存盘（${snapText.length} 字节）`);
  if (secrets.some((s) => s.length >= 8 && snapText.includes(s))) {
    /* 理论上不会发生（快照只保存 API 的 result），但这是硬约束，必须自检 */
    errLog('  🛑 快照里检出了令牌明文 —— 这是本工具不该出现的状态，已中止，未发出 PUT。');
    return EXIT_LOCAL_ERROR;
  }

  /* ② 合并并 PUT */
  const merge = planMerge(currentRules, managedRules);
  const body = { rules: merge.rules };
  log(`\n  [3] PUT ${epUrl}`);
  log(`      合并：别人的规则保留 ${merge.keptForeign} 条 · 本工具旧规则替换 ${merge.replacedManaged} 条 · 写入 ${managedRules.length} 条`);
  log(`      请求头：${headerSummary}`);
  log(`      请求体：\n${JSON.stringify(body, null, 2).split('\n').map((l) => '      ' + l).join('\n')}`);

  const put = await send({ method: 'PUT', url: epUrl, headers: authHeader, body });
  const putCode = handleResponse('下发', put);
  if (putCode !== EXIT_OK) {
    errLog(`\n   现状**未按本工具预期**修改（或部分修改）。快照仍在：${snapPath}`);
    errLog(`   回滚命令：node src/deploy/cloudflare.mjs --zone ${zoneRef} --rollback "${snapPath}" --apply --base-url ${baseUrl}`);
    return putCode;
  }

  log('\n✅ 下发完成。');
  log(`   规则：${currentRules.length} 条 → ${merge.rules.length} 条`);
  log(`   回滚命令：node src/deploy/cloudflare.mjs --zone ${zoneRef} --rollback "${snapPath}" --apply --base-url ${baseUrl}`);
  log('   注意：控制台里手工改名/删除本工具的规则后，回滚仍会以快照为准整体还原（本工具只认 header-forge: 前缀）。');
  return EXIT_OK;
}

/* ============================== 入口 ============================== */

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (invokedDirectly) {
  runDeploy(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(`\n🛑 运行失败：${err.message}`);
      process.exit(EXIT_LOCAL_ERROR);
    });
}
