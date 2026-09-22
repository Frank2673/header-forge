/**
 * Vercel 生成器
 *
 * 输出 `vercel.json` 的 headers 段。已存在 vercel.json 时可人工合并，
 * 因此这里同时提供「独立文件」与「片段」两种输出。
 *
 * @module generators/vercel
 */

export const id = 'vercel';
export const label = 'Vercel';
export const filename = 'vercel.json';

export function generate(policy, options = {}) {
  const source = options.source || '/(.*)';

  const headers = Object.values(policy.headers).map((h) => ({
    key: h.name,
    value: h.value,
  }));

  const config = {
    $schema: 'https://openapi.vercel.sh/vercel.json',
    headers: [{ source, headers }],
  };

  return {
    id,
    label,
    filename,
    content: JSON.stringify(config, null, 2) + '\n',
    /* 便于合并进已有配置 */
    fragment: JSON.stringify({ headers: config.headers }, null, 2),
    notes: [
      '若仓库已有 vercel.json，请只合并 headers 段，不要整体覆盖',
      'source 使用 Vercel 的路径语法：/(.*) 表示全部路径',
    ],
  };
}
