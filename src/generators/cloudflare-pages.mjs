/**
 * Cloudflare Pages 生成器
 *
 * 用 `_headers` 文件声明响应头。放在站点根目录即可生效，免费套餐支持。
 * 这是 GitHub Pages 最实际的替代/前置方案之一。
 *
 * @module generators/cloudflare-pages
 */

import { renderHeadersFile } from './headers-file.mjs';

export const id = 'cloudflare-pages';
export const label = 'Cloudflare Pages';
export const filename = '_headers';

export function generate(policy, options = {}) {
  const content = renderHeadersFile(policy, {
    pathPattern: options.pathPattern || '/*',
    notes: [
      '由 header-forge 生成 —— 请勿手工编辑，改 headers.policy.json 后重新生成',
      '用法：把本文件放到站点发布目录的根目录（与 index.html 同级）',
      '文档：https://developers.cloudflare.com/pages/configuration/headers/',
    ],
  });

  return {
    id,
    label,
    filename,
    content,
    notes: [
      'Cloudflare Pages 免费套餐即支持 _headers 文件，无需自定义域名（可用 *.pages.dev）',
      '若站点同时部署在 GitHub Pages，注意 GitHub Pages 不支持响应头，需要由 Cloudflare 侧代理',
    ],
  };
}
