/**
 * Caddy 生成器
 *
 * Caddy 的 header 指令写在站点块内，语法比 nginx 简洁，且默认不会有 add_header 的继承陷阱。
 *
 * @module generators/caddy
 */

export const id = 'caddy';
export const label = 'Caddy';
export const filename = 'Caddyfile.headers';

/**
 * 转义 Caddy 字符串（双引号包裹，转义反斜杠与引号）
 */
export function escapeCaddyValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function generate(policy, options = {}) {
  const siteAddress = options.siteAddress || 'example.com';

  const lines = [];
  lines.push('# 由 header-forge 生成 —— 请勿手工编辑，改 headers.policy.json 后重新生成');
  lines.push('# 把 header 块放进站点块内；下方示例假设站点地址为 ' + siteAddress);
  lines.push('');
  lines.push(`${siteAddress} {`);
  lines.push('\theader {');

  for (const header of Object.values(policy.headers)) {
    lines.push(`\t\t${header.name} "${escapeCaddyValue(header.value)}"`);
  }

  /* Caddy 允许直接删除响应头 —— 这点比 nginx 方便 */
  for (const name of policy.remove || []) {
    lines.push(`\t\t-${name}`);
  }

  lines.push('\t}');
  lines.push('\tfile_server');
  lines.push('}');
  lines.push('');

  return {
    id,
    label,
    filename,
    notes: [
      'Caddy 用 -HeaderName 语法直接删除响应头（nginx 需要 more_clear_headers 模块）',
      'header 指令默认作用于所有响应，无需像 nginx 那样加 always',
    ],
    content: lines.join('\n'),
  };
}
