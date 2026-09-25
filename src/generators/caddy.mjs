/**
 * Caddy 生成器
 *
 * Caddy 的 header 指令写在站点块内，语法比 nginx 简洁，且默认不会有 add_header 的继承陷阱。
 *
 * 安全要点：值会被渲染进 Caddyfile 语法，因此必须转义反斜杠与双引号 ——
 * 策略层已拒绝含换行/制表的值，这里再加一道断言（策略层的校验是第一道关，
 * 但绕过策略层直接调用生成器的路径也必须拒绝，而不是渲染出可注入的配置）。
 *
 * `remove` 列表尤其要小心：它渲染成裸的 `-${name}`，一个带换行的条目
 * 可以直接关掉 header 块、注入任意 caddy 指令（策略层现已同样校验，
 * 这里是第二道关 —— 因为"漏掉一个渲染点"就等于没堵住）。
 *
 * @module generators/caddy
 */

import { isSafeHeaderName } from '../lib/policy.mjs';

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
    if (/[\r\n\t\0]/.test(String(header.value))) {
      throw new Error(
        `${header.name} 的 value 含换行/制表等字符 —— 会被注入进 Caddyfile 的指令语法，拒绝渲染`
      );
    }
    lines.push(`\t\t${header.name} "${escapeCaddyValue(header.value)}"`);
  }

  /* Caddy 允许直接删除响应头 —— 这点比 nginx 方便。
     `-${name}` 是裸渲染，所以这里的名字必须过 token 校验：一个换行就能
     关掉 header 块并注入任意指令（如把页面 302 到攻击者站点）。 */
  for (const name of policy.remove || []) {
    if (!isSafeHeaderName(String(name))) {
      throw new Error(
        `remove 里的「${String(name).replace(/[\r\n\t\0]/g, '␍')}」不是合法的响应头名 —— ` +
          '会被注入进 Caddyfile 的指令语法，拒绝渲染'
      );
    }
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
