/**
 * 反向导入：读现有配置 → 生成策略文件
 *
 * 场景是"接管别人的项目"：仓库里已经有一份 `_headers` / `vercel.json` /
 * nginx 片段 / Caddyfile，你想把它纳入「策略即代码」的管治，而不是从零重写。
 *
 * 三个设计决定：
 *
 * 1. **忠实反映现状，而不是顺手修正**。导入出来的策略**可能不满足安全基线** ——
 *    那正是要展示给用户的差距。如果导入时自动"补齐"缺失的头，用户会以为
 *    站点已经有这些头，这是最危险的失败方式。
 * 2. **解析不了的行不静默丢弃**。都进 skipped，在报告里列出来。
 * 3. **只恢复得回"名字与取值"**。severity / why 是人的判断，配置里没有，
 *    导入时给占位值并标注"尚未人工确认"。
 *
 * 验收标准是**往返一致**：generate 出来的配置，import 回去必须得到同一组
 * 名字与取值（nginx / caddy 的转义要能正确逆转）。
 *
 * @module importer
 */

import { canonicalHeaderName, collectPolicyProblems } from './lib/policy.mjs';
import { parseHeadersFile } from './generators/headers-file.mjs';

/** 支持的导入格式 */
export const IMPORT_FORMATS = ['headers', 'vercel', 'nginx', 'caddy'];

/**
 * 本工具管治的响应头（安全类）
 *
 * 为什么要有这个白名单：真实世界的 `_headers` 文件里，`Cache-Control` 往往是
 * **按路径分别取值**的（抓了 9 份公开仓库的配置，4 份都是这个形态，最多一份
 * 有 14 个路径块）。而策略模型是「一个头一个取值」——
 * 把这些头导进来会压平它们的按路径差异，用户一旦"导入 → 改名 → generate → 发布"，
 * 就会用一条规则替换掉对方整套缓存策略，**直接搞坏线上缓存**。
 *
 * 根因是分类错误：`Cache-Control` / `Content-Type` / `Access-Control-*` 不是安全响应头，
 * 本工具不该接管它们。默认只导入安全类，其余明确报告为"未接管"。
 * 确实需要全量导入时用 --all（此时按路径冲突会给出警告）。
 */
export const SECURITY_HEADERS = new Set([
  'Strict-Transport-Security',
  'Content-Security-Policy',
  'Content-Security-Policy-Report-Only',
  'X-Content-Type-Options',
  'X-Frame-Options',
  'X-Xss-Protection',
  'Referrer-Policy',
  'Permissions-Policy',
  'Cross-Origin-Opener-Policy',
  'Cross-Origin-Embedder-Policy',
  'Cross-Origin-Resource-Policy',
  'X-Permitted-Cross-Domain-Policies',
  'X-Download-Options',
  'X-Dns-Prefetch-Control',
  'Clear-Site-Data',
]);

/** 从现有配置导入的头，其 why 字段的占位说明 */
const IMPORTED_WHY = '（从现有配置导入，尚未人工确认）';

/**
 * 猜测格式：优先看文件名，其次看内容特征
 * @param {string} text
 * @param {string} [filename]
 * @returns {string|null}
 */
export function detectFormat(text, filename = '') {
  const name = String(filename).toLowerCase();
  const content = String(text ?? '');

  if (/vercel\.json$/.test(name)) return 'vercel';
  if (/(^|\/)Caddyfile/i.test(filename) || /caddyfile/i.test(name)) return 'caddy';
  if (/\.conf$/.test(name) || /nginx/i.test(name)) return 'nginx';
  if (/_headers$/.test(name) || /netlify|cloudflare/i.test(name)) return 'headers';

  /* 内容特征 */
  const trimmed = content.trim();
  if (trimmed.startsWith('{')) {
    try {
      const json = JSON.parse(trimmed);
      if (json && Array.isArray(json.headers)) return 'vercel';
    } catch {
      /* 不是合法 JSON，继续按文本判断 */
    }
  }
  if (/^\s*add_header\s+/m.test(content)) return 'nginx';
  if (/^\s*header\s*\{/m.test(content) || /^\s*-[A-Za-z0-9-]+\s*$/m.test(content)) return 'caddy';
  if (/^\S.*$/m.test(content) && /^\s+[A-Za-z0-9-]+:\s*\S/m.test(content)) return 'headers';

  return null;
}

/** 逆转 nginx / caddy 双引号字符串里的转义（`\"` → `"`，`\\` → `\`） */
export function unescapeQuoted(text) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\\' && i + 1 < text.length && (text[i + 1] === '"' || text[i + 1] === '\\')) {
      out += text[i + 1];
      i += 1;
      continue;
    }
    out += text[i];
  }
  return out;
}

/**
 * 内部：累加头部
 *
 * @param {(name: string) => boolean} keep 哪些头要接管（不接管的进 ignored，且不参与冲突检测 ——
 *   否则会给"根本不导入的头"报冲突，把真正的问题淹没在噪音里）
 */
function makeCollector(keep = () => true) {
  const headers = {};
  const ignored = new Map();
  const remove = [];
  const skipped = [];
  const warnings = [];
  /* 记录被保留的头里出现了冲突取值的那些名字，供上层决定要不要提"多路径块" */
  const conflicts = new Set();

  return {
    headers,
    remove,
    skipped,
    warnings,
    conflicts,
    get ignored() {
      return [...ignored.entries()].map(([name, value]) => ({
        name,
        value,
        reason: '不属于安全响应头，本工具不接管（它常按路径取值，压平会改变线上行为）',
      }));
    },
    set(name, value, where) {
      const canonical = canonicalHeaderName(name);

      if (!keep(canonical)) {
        ignored.set(canonical, value);
        return;
      }

      if (headers[canonical] !== undefined && headers[canonical] !== value) {
        conflicts.add(canonical);
        warnings.push(
          `${canonical} 出现了多个取值（${where}）：保留后出现的「${value}」，丢弃「${headers[canonical]}」\n` +
            `      策略模型里一个头只能有一个取值；若确实需要按路径区分，请拆成多份策略`
        );
      }
      headers[canonical] = value;
    },
    /* 记下一处解析不了的内容。参数顺序：where 是位置说明（如「整个文件」「header 块」），
       line 是原文 —— 打印成 `[where] line` 时读起来通顺。 */
    skip(where, line) {
      skipped.push({ where: String(where), line: String(line ?? '').trim() });
    },
    drop(name) {
      const canonical = canonicalHeaderName(name);
      if (!remove.includes(canonical)) remove.push(canonical);
    },
  };
}

/**
 * 解析 `_headers`（Cloudflare Pages / Netlify）
 *
 * 多路径块会被合并成一张表 —— 策略模型里一个头只有一个取值。
 * 只有在**被保留的头**确实出现冲突取值时才提"多路径块"：否则那条提示会变成
 * 噪音（真实配置里几乎每个文件都有多个路径块，多数只是重复相同的安全头）。
 */
export function parseHeadersConfig(text, keep) {
  const c = makeCollector(keep);
  const blocks = parseHeadersFile(text);

  if (blocks.length === 0) {
    c.skip('(整个文件)', '没有解析出任何路径块');
    return c;
  }

  for (const block of blocks) {
    for (const [name, value] of Object.entries(block.headers)) {
      c.set(name, value, `路径 ${block.pattern}`);
    }
  }

  if (blocks.length > 1 && c.conflicts.size > 0) {
    c.warnings.push(
      `文件里有 ${blocks.length} 个路径块（${blocks.map((b) => b.pattern).join(', ')}），` +
        `其中 ${[...c.conflicts].join(', ')} 的取值按路径不同 —— 已合并为一张表，这层区分会丢失`
    );
  }

  return c;
}

/**
 * 解析 nginx 的 add_header 指令
 *
 * 只认 `add_header <名> "<值>" [always];`（值也可不带引号）。
 * 不解析 location 嵌套结构 —— 结构信息会被记入 warning，因为在策略模型里表达不了。
 */
export function parseNginxHeaders(text, keep) {
  const c = makeCollector(keep);
  const re = /^\s*add_header\s+([A-Za-z0-9_-]+)\s+("(?:[^"\\]|\\.)*"|'[^']*'|\S+)\s*(always\s*)?;/gim;

  let match;
  let found = 0;
  while ((match = re.exec(String(text))) !== null) {
    found += 1;
    const raw = match[2];
    const value = /^"/.test(raw) ? unescapeQuoted(raw.slice(1, -1)) : raw.replace(/^'|'$/g, '');
    c.set(match[1], value, 'add_header');
  }

  if (found === 0) {
    c.skip('(整个文件)', '没有找到 add_header 指令');
    return c;
  }

  if (/location\s/.test(String(text))) {
    c.warnings.push(
      '文件里有 location 块 —— nginx 的 add_header 在子级 location 里会覆盖父级，' +
        '策略模型表达不了这层结构；导入结果只反映"文件里写了哪些头"'
    );
  }

  return c;
}

/**
 * 解析 Caddyfile 的 header 块
 *
 * 支持 `Name "value"` 与删除指令 `-Name`。
 * 用花括号深度定位 header 块，避免把站点块里的其它指令当成响应头。
 */
export function parseCaddyHeaders(text, keep) {
  const c = makeCollector(keep);
  const lines = String(text).split(/\r?\n/);

  let depth = 0;
  let inHeaderBlock = false;
  let headerBlockDepth = -1;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const opens = (trimmed.match(/\{/g) || []).length;
    const closes = (trimmed.match(/\}/g) || []).length;

    if (!inHeaderBlock && /^header\s*\{?\s*$/.test(trimmed)) {
      inHeaderBlock = true;
      headerBlockDepth = depth + opens;
      depth += opens - closes;
      continue;
    }

    if (inHeaderBlock) {
      if (depth < headerBlockDepth || closes > 0) {
        /* 最内层闭合 —— 结束 header 块 */
        inHeaderBlock = false;
        depth += opens - closes;
        continue;
      }

      /* 删除指令：本工具生成的是 `-Name`，但手写配置里也常见 `- Name`，两种都认 */
      const drop = trimmed.match(/^-\s*([A-Za-z0-9_-]+)\s*$/);
      if (drop) {
        c.drop(drop[1]);
      } else {
        const set = trimmed.match(/^([A-Za-z0-9_-]+)\s+("(?:[^"\\]|\\.)*"|'[^']*'|\S+)\s*$/);
        if (set && set[1] !== '-') {
          const raw = set[2];
          const value = /^"/.test(raw) ? unescapeQuoted(raw.slice(1, -1)) : raw.replace(/^'|'$/g, '');
          c.set(set[1], value, 'header 块');
        } else {
          c.skip('header 块', line);
        }
      }

      depth += opens - closes;
      continue;
    }

    depth += opens - closes;
  }

  if (Object.keys(c.headers).length === 0 && c.remove.length === 0) {
    c.skip('(整个文件)', '没有找到 header 块');
  }

  return c;
}

/**
 * 解析 vercel.json 的 headers 段
 *
 * 多条 source 规则会合并；取值冲突时记入 warnings。
 */
export function parseVercelHeaders(text, keep) {
  const c = makeCollector(keep);

  let json;
  try {
    json = JSON.parse(String(text));
  } catch (err) {
    c.skip('(整个文件)', `不是合法 JSON：${err.message}`);
    return c;
  }

  const rules = Array.isArray(json?.headers) ? json.headers : [];
  if (rules.length === 0) {
    c.skip('(整个文件)', '没有 headers 数组（或为空）—— 注意 vercel.json 里 headers 与 redirects 是不同字段');
    return c;
  }

  for (const rule of rules) {
    const source = rule?.source || '/(.*)';
    const list = Array.isArray(rule?.headers) ? rule.headers : [];
    for (const entry of list) {
      if (!entry || typeof entry.key !== 'string' || typeof entry.value !== 'string') {
        c.skip('headers 条目', JSON.stringify(entry));
        continue;
      }
      c.set(entry.key, entry.value, `source ${source}`);
    }
  }

  if (rules.length > 1 && c.conflicts.size > 0) {
    c.warnings.push(
      `vercel.json 里有 ${rules.length} 条 source 规则（${rules.map((r) => r?.source || '/(.*)').join(', ')}），` +
        `其中 ${[...c.conflicts].join(', ')} 的取值按 source 不同 —— 已合并为一张表，这层区分会丢失`
    );
  }

  return c;
}

const PARSERS = {
  headers: parseHeadersConfig,
  vercel: parseVercelHeaders,
  nginx: parseNginxHeaders,
  caddy: parseCaddyHeaders,
};

/**
 * 解析现有配置
 *
 * @param {string} text
 * @param {object} [options]
 * @param {string} [options.format] 指定格式；不给则自动识别
 * @param {string} [options.filename] 用于识别格式
 * @param {'security'|'all'} [options.include='security'] 导入范围
 * @returns {{ok: boolean, error?: string, format?: string, headers?: object, remove?: string[],
 *            ignored?: Array<{name:string,value:string,reason:string}>, skipped?: Array, warnings?: Array}}
 */
export function importConfig(text, options = {}) {
  const format = options.format || detectFormat(text, options.filename);
  const include = options.include === 'all' ? 'all' : 'security';

  if (!format) {
    return {
      ok: false,
      error:
        '无法识别配置格式。请用 --format 明确指定（' +
        IMPORT_FORMATS.join(' / ') +
        '），或检查文件内容是否为空。',
    };
  }

  if (!PARSERS[format]) {
    return { ok: false, error: `不支持的格式：${format}（可选：${IMPORT_FORMATS.join(' / ')}）` };
  }

  /* 默认只接管安全类响应头；其余明确报告为"未接管"而不是悄悄丢掉。
     过滤在收集阶段就生效（见 makeCollector），所以非安全头的按路径冲突
     不会产生噪音警告 —— 那些头我们根本不导入，报它们的冲突只会淹没真正的问题。 */
  const keep = include === 'all' ? () => true : (name) => SECURITY_HEADERS.has(name);
  const collected = PARSERS[format](text, keep);

  const headers = collected.headers;
  const ignored = collected.ignored;
  const headerCount = Object.keys(headers).length;

  if (headerCount === 0 && collected.remove.length === 0) {
    const onlyNonSecurity = ignored.length > 0;
    return {
      ok: false,
      error: onlyNonSecurity
        ? `文件里有 ${ignored.length} 个响应头，但都不是安全响应头（${ignored.map((i) => i.name).join(', ')}）——` +
          `本工具不接管它们。若确实要全量导入，请加 --all。`
        : `按 ${format} 格式解析完成，但没有得到任何响应头。`,
      format,
      skipped: collected.skipped,
      ignored,
    };
  }

  return {
    ok: true,
    format,
    headers,
    remove: collected.remove,
    ignored,
    skipped: collected.skipped,
    warnings: collected.warnings,
    headerCount,
  };
}

/**
 * 把导入结果转成策略草稿
 *
 * 忠实反映现状：不补缺失的头、不改弱值 —— 这些差距由 analyzeImport 报出来。
 *
 * @param {{headers: object, remove?: string[]}} imported
 * @returns {object} 可直接 JSON.stringify 的策略对象
 */
export function buildPolicyDraft(imported) {
  const headers = {};
  for (const [name, value] of Object.entries(imported.headers)) {
    headers[name] = {
      value,
      severity: 'info',
      why: IMPORTED_WHY,
      allowStronger: true,
    };
  }

  const draft = { version: 1, targets: {}, headers };
  if (imported.remove && imported.remove.length) draft.remove = [...imported.remove];
  return draft;
}

/**
 * 一步到位：解析 + 转草稿 + 算出与安全基线的差距
 *
 * @param {string} text
 * @param {object} [options]
 * @returns {{ok: boolean, error?: string, format?: string, draft?: object, gaps?: string[], imported?: object}}
 */
export function analyzeImport(text, options = {}) {
  const imported = importConfig(text, options);
  if (!imported.ok) return { ok: false, error: imported.error, format: imported.format };

  const draft = buildPolicyDraft(imported);

  /* 用基线校验器算差距；结构性问题（理论上不会出现）也当 gap 报出来 */
  let gaps = [];
  try {
    gaps = collectPolicyProblems(draft).problems;
  } catch (err) {
    gaps = [err.message];
  }

  return { ok: true, format: imported.format, draft, gaps, imported };
}
