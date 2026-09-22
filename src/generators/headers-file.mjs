/**
 * `_headers` 文件格式的渲染与解析
 *
 * Cloudflare Pages 与 Netlify 都使用这一格式，因此渲染/解析逻辑共用一份。
 * 解析器不只是为了对称 —— 本地模拟器靠它把「生成的配置文件」变成真实响应头，
 * 从而证明「生成的产物确实能达到策略要求」，而不是只验证策略对象本身。
 *
 * 格式示例：
 *   /*
 *     X-Content-Type-Options: nosniff
 *     Referrer-Policy: strict-origin-when-cross-origin
 *
 * @module generators/headers-file
 */

import { canonicalHeaderName } from '../lib/policy.mjs';

/**
 * 渲染 `_headers` 内容
 * @param {object} policy
 * @param {object} options
 * @param {string} [options.pathPattern='/*']
 * @param {string[]} [options.notes] 注释行（以 # 开头）
 * @returns {string}
 */
export function renderHeadersFile(policy, options = {}) {
  const { pathPattern = '/*', notes = [] } = options;
  const lines = [];

  for (const note of notes) lines.push(`# ${note}`);
  if (notes.length) lines.push('');

  lines.push(pathPattern);
  for (const header of Object.values(policy.headers)) {
    lines.push(`  ${header.name}: ${header.value}`);
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * 解析 `_headers` 内容
 *
 * 支持：注释行（#）、路径行（无缩进）、头部行（有缩进）、多路径块。
 * 解析失败的行会被跳过而不是抛错（配置文件是外部输入，容错优先）。
 *
 * @param {string} text
 * @returns {Array<{pattern: string, headers: Record<string,string>}>}
 */
export function parseHeadersFile(text) {
  const blocks = [];
  let current = null;

  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.replace(/\s+$/, '');
    if (!line.trim()) continue;
    if (line.trim().startsWith('#')) continue;

    const isIndented = /^\s/.test(line);
    if (!isIndented) {
      /* 新的路径块 */
      current = { pattern: line.trim(), headers: {} };
      blocks.push(current);
      continue;
    }

    if (!current) continue; // 没有归属路径的头部行，忽略

    const match = line.trim().match(/^([^:]+):\s*(.*)$/);
    if (!match) continue;

    current.headers[canonicalHeaderName(match[1].trim())] = match[2].trim();
  }

  return blocks;
}

/**
 * 把 `_headers` 中匹配某路径的头部合并成一张表（后匹配的覆盖先匹配的）
 * @param {string} text
 * @param {string} path
 * @returns {Record<string,string>}
 */
export function resolveHeadersForPath(text, path = '/') {
  const out = {};
  for (const block of parseHeadersFile(text)) {
    if (matchesPattern(block.pattern, path)) Object.assign(out, block.headers);
  }
  return out;
}

/**
 * `_headers` 的路径匹配：支持 /* 通配与精确路径
 */
export function matchesPattern(pattern, path) {
  if (pattern === '/*' || pattern === '*') return true;
  if (pattern.endsWith('/*')) return path.startsWith(pattern.slice(0, -1));
  return pattern === path;
}
