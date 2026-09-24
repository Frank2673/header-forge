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

/** 内部：累加头部，重复时记入 warnings */
function makeCollector() {
  const headers = {};
  const remove = [];
  const skipped = [];
  const warnings = [];

  return {
    headers,
    remove,
    skipped,
    warnings,
    set(name, value, where) {
      const canonical = canonicalHeaderName(name);
      if (headers[canonical] !== undefined && headers[canonical] !== value) {
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
 * 若不同块给出不同取值，记入 warnings（不静默择一）。
 */
export function parseHeadersConfig(text) {
  const c = makeCollector();
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

  if (blocks.length > 1) {
    c.warnings.push(
      `文件里有 ${blocks.length} 个路径块（${blocks.map((b) => b.pattern).join(', ')}）——` +
        `已合并为一张表；若各路径的取值本就不同，导入结果会丢失这层区分`
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
export function parseNginxHeaders(text) {
  const c = makeCollector();
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
export function parseCaddyHeaders(text) {
  const c = makeCollector();
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
export function parseVercelHeaders(text) {
  const c = makeCollector();

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

  if (rules.length > 1) {
    c.warnings.push(
      `vercel.json 里有 ${rules.length} 条 source 规则（${rules.map((r) => r?.source || '/(.*)').join(', ')}）——` +
        `已合并为一张表；按路径区分不同取值的能力会在导入时丢失`
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
 * @returns {{ok: boolean, error?: string, format?: string, headers?: object, remove?: string[], skipped?: Array, warnings?: Array}}
 */
export function importConfig(text, options = {}) {
  const format = options.format || detectFormat(text, options.filename);

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

  const collected = PARSERS[format](text);
  const headerCount = Object.keys(collected.headers).length;

  if (headerCount === 0 && collected.remove.length === 0) {
    return {
      ok: false,
      error: `按 ${format} 格式解析完成，但没有得到任何响应头。`,
      format,
      skipped: collected.skipped,
    };
  }

  return {
    ok: true,
    format,
    headers: collected.headers,
    remove: collected.remove,
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
