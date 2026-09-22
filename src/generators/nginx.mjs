/**
 * Nginx 生成器
 *
 * 输出可直接放进 server 块的 add_header 指令。
 *
 * 安全要点：值会被渲染进 nginx 配置语法，因此必须转义反斜杠与双引号 ——
 * 否则策略里一个引号就能截断指令、注入额外配置（配置注入）。
 *
 * @module generators/nginx
 */

export const id = 'nginx';
export const label = 'Nginx';
export const filename = 'nginx-security-headers.conf';

/**
 * 转义 nginx 双引号字符串中的特殊字符
 */
export function escapeNginxValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function generate(policy) {
  const lines = [];
  lines.push('# 由 header-forge 生成 —— 请勿手工编辑，改 headers.policy.json 后重新生成');
  lines.push('# 把下面内容放进 server { ... } 块内（通常紧跟在 listen / server_name 之后）');
  lines.push('#');
  lines.push('# 注意 nginx 的 add_header 继承规则：子级 location 若自行 add_header，');
  lines.push('# 父级的所有 add_header 都会失效。若存在多级 location，请在各处重复声明。');
  lines.push('');

  for (const header of Object.values(policy.headers)) {
    lines.push(`add_header ${header.name} "${escapeNginxValue(header.value)}" always;`);
  }

  lines.push('');
  lines.push('# always 参数确保错误响应（4xx/5xx）也带上这些头');
  lines.push('');

  return {
    id,
    label,
    filename,
    content: lines.join('\n'),
    notes: [
      'add_header 的继承陷阱：内层 location 一旦有 add_header，外层全部失效',
      '若使用反向代理，注意不要重复添加同名头（可能产生两个值）',
    ],
  };
}
