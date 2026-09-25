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
import * as htaccess from './htaccess.mjs';

export const GENERATORS = {
  [cloudflarePages.id]: cloudflarePages,
  [netlify.id]: netlify,
  [vercel.id]: vercel,
  [nginx.id]: nginx,
  [caddy.id]: caddy,
  [htaccess.id]: htaccess,
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

/**
 * 规划每份产物的落盘路径
 *
 * 为什么需要它：Cloudflare Pages 与 Netlify 都输出 `_headers`（格式相同、注释不同）。
 * 如果直接按文件名写入，两者会落在同一个路径 —— **谁后写谁生效**，
 * 结果取决于生成器的遍历顺序。那样"生成产物"就带上了静默的不确定性：
 * 同一份策略在不同版本、不同 --only 组合下可能产出不同的文件。
 *
 * 规则：
 *   - nginx / caddy 与带路径的产物，一直放自己的子目录
 *   - 其余产物放 outDir 根下；**若该名字已被占用**，则放进自己的子目录并标记 disambiguated
 *
 * 特例：Apache 的 `.htaccess` 落在 outDir 根下 —— 它不是"某一家的托管配置"，
 * 而必须与 index.html 同目录才对整个站点生效（进子目录就等于只对一个子路径生效）。
 * 它与 `_headers` 不撞名，所以不会被消歧逻辑挪走。
 *
 * @param {string} outDir
 * @param {Array<{id:string,filename:string}>} artifacts
 * @returns {Array<{artifact: object, target: string, disambiguated: boolean}>}
 */
export function planOutputPaths(outDir, artifacts) {
  const taken = new Set();

  return artifacts.map((artifact) => {
    const nested = artifact.filename.includes('/') || artifact.id === 'nginx' || artifact.id === 'caddy';

    let target = nested
      ? `${outDir}/${artifact.id}/${artifact.filename}`
      : `${outDir}/${artifact.filename}`;
    let disambiguated = false;

    if (taken.has(target)) {
      target = `${outDir}/${artifact.id}/${artifact.filename}`;
      disambiguated = true;
    }
    taken.add(target);

    return { artifact, target, disambiguated };
  });
}
