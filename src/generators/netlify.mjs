/**
 * Netlify 生成器
 *
 * 同样使用 `_headers` 文件（格式与 Cloudflare Pages 一致，但路径匹配规则略有差别）。
 *
 * @module generators/netlify
 */

import { renderHeadersFile } from './headers-file.mjs';

export const id = 'netlify';
export const label = 'Netlify';
export const filename = '_headers';

export function generate(policy, options = {}) {
  const content = renderHeadersFile(policy, {
    pathPattern: options.pathPattern || '/*',
    notes: [
      '由 header-forge 生成 —— 请勿手工编辑，改 headers.policy.json 后重新生成',
      '用法：把本文件放到发布目录根目录（publish 目录），随站点一起部署',
      '文档：https://docs.netlify.com/routing/headers/',
    ],
  });

  return {
    id,
    label,
    filename,
    content,
    notes: [
      'Netlify 的路径匹配比 Cloudflare 更严格：/* 不会自动覆盖带扩展名的路径，必要时显式列出',
      '免费套餐即可使用，无需自定义域名（可用 *.netlify.app）',
    ],
  };
}
