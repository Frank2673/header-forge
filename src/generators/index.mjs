/**
 * 生成器注册表
 *
 * @module generators
 */

import * as cloudflarePages from './cloudflare-pages.mjs';
import * as netlify from './netlify.mjs';
import * as vercel from './vercel.mjs';
import * as nginx from './nginx.mjs';
import * as caddy from './caddy.mjs';

export const GENERATORS = {
  [cloudflarePages.id]: cloudflarePages,
  [netlify.id]: netlify,
  [vercel.id]: vercel,
  [nginx.id]: nginx,
  [caddy.id]: caddy,
};

export const GENERATOR_IDS = Object.keys(GENERATORS);

/**
 * 用全部（或指定）生成器产出配置
 * @param {object} policy
 * @param {object} options
 * @param {string[]} [options.only] 只运行指定生成器
 * @returns {Array<{id,label,filename,content,notes}>}
 */
export function generateAll(policy, options = {}) {
  const ids = options.only && options.only.length ? options.only : GENERATOR_IDS;

  const unknown = ids.filter((id) => !GENERATORS[id]);
  if (unknown.length) {
    throw new Error(`未知的生成器：${unknown.join(', ')}（可选：${GENERATOR_IDS.join(', ')}）`);
  }

  return ids.map((id) => GENERATORS[id].generate(policy, options));
}

export { parseHeadersFile, resolveHeadersForPath, matchesPattern } from './headers-file.mjs';
