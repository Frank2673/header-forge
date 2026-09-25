/**
 * Apache `.htaccess` 生成器（响应头由 `mod_headers` 提供）
 *
 * 与其它四个生成器有三处不同，三处都写进了产物注释里（因为踩到任何一处都会表现为
 * 「配置写了但没生效」，而这正是本项目最想消灭的失败方式）：
 *
 * 1. `.htaccess` 是**文件级**配置。它只在两个前置条件同时满足时才生效：
 *    服务器加载了 `mod_headers`，且该目录允许覆盖（主配置里 `AllowOverride FileInfo` ——
 *    `Header` 指令的 Override 类别是 FileInfo）。前置条件不满足时不会有任何报错。
 * 2. 用 `<IfModule mod_headers.c>` 守卫。取舍如下：mod_headers 缺失时，没有守卫会让
 *    整个目录返回 500（.htaccess 里的未知指令是致命错误），有守卫则退化为静默不生效。
 *    这里选**可用性优先**（整站 500 比不生效严重得多），代价是失败无声 ——
 *    因此产物注释与 README 都明确要求部署后用 `verify` 复验。
 * 3. 全部用 `Header always set`（而不是 `Header set`）。`Header set` 只作用于**成功响应**，
 *    404/500 错误页会丢掉全部防护 —— 而错误页同样是浏览器会渲染的 HTML，
 *    一样可以被打框架（点击劫持）、被 MIME 嗅探、被当作脚本执行。
 *    代价：`always` 也会作用于 3xx/4xx/5xx；若后端应用自己也设置同名头，
 *    需保证两边取值一致（`set` 替换同名头，但不同表在部分配置下可能产生重复值）。
 *
 * 安全要点与 nginx / caddy 一致：值会被渲染进配置语法，所以必须转义 `\` 与 `"`。
 * 策略层的注入防护（拒绝含换行/制表符的值）是第一道关，这个模块再加一道断言 ——
 * 因为策略层的 `remove` 数组**没有**做同样的校验，直接渲染就是配置注入。
 *
 * @module generators/htaccess
 */

import { canonicalHeaderName } from '../lib/policy.mjs';

export const id = 'htaccess';
export const label = 'Apache .htaccess';
export const filename = '.htaccess';

/** 头部名 token 规则（与 lib/policy.mjs 的 TOKEN_RE 同规则） */
const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** 会破坏配置语法的控制字符：换行/回车/制表/空字节 */
const INJECTION_RE = /[\r\n\t\0]/;

/** mod_headers 里"直接赋值"类的动词（`Header <verb> <名字> <值>`） */
const SET_VERBS = new Set(['set', 'setifempty', 'add', 'addifempty', 'append', 'merge']);

/** 删除类动词 */
const UNSET_VERBS = new Set(['unset', 'unsetifempty']);

/**
 * 转义 Apache 双引号字符串里的特殊字符
 *
 * Apache 用 ap_getword_conf() 解析指令参数：引号内的 `\"` 是字面引号、`\\` 是字面反斜杠。
 * 转义顺序必须是先反斜杠后引号，否则 `\` 会被二次转义。
 */
export function escapeApacheValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * 逆转义 —— 必须与 escapeApacheValue 严格互逆（往返一致性的基础）
 *
 * 语义与 importer 的 unescapeQuoted 相同（`\"` → `"`、`\\` → `\`，其它 `\x` 原样保留）；
 * 之所以不复用同一个函数，是为了不让生成器反向依赖 importer（会形成循环导入）。
 * 两者的一致性由 tests/htaccess.test.mjs 的交叉核对用例守住。
 */
export function unescapeApacheValue(text) {
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

/**
 * 取出一条指令的参数值
 *
 * Apache 的引号可以是双引号也可以是单引号；引号外的内容按空白分词。
 * 值之后允许跟 `early`、`env=!var` 这类 Apache 自己的参数 —— 它们不是值的一部分，忽略。
 *
 * @param {string} rest 名字之后的原文
 * @returns {string}
 */
export function readApacheArg(rest) {
  const text = String(rest ?? '').trim();
  if (!text) return '';

  const quote = text[0];
  if (quote !== '"' && quote !== "'") return text.split(/\s+/)[0];

  let out = '';
  for (let i = 1; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\\' && i + 1 < text.length && (text[i + 1] === quote || text[i + 1] === '\\')) {
      out += text[i + 1];
      i += 1;
      continue;
    }
    if (ch === quote) break;
    out += ch;
  }
  return out;
}

/**
 * 渲染 `.htaccess`
 *
 * @param {object} policy 已校验的策略（policy.headers / policy.remove）
 * @returns {{id,label,filename,content,notes}}
 */
export function generate(policy) {
  const lines = [];

  lines.push('# 由 header-forge 生成 —— 请勿手工编辑，改 headers.policy.json 后重新生成');
  lines.push('# 用法：放到站点文档根目录（与 index.html 同级）；它对该目录及其子目录生效。');
  lines.push('#');
  lines.push('# 生效需要两个前置条件（缺任何一个，下面这块配置都不会生效）：');
  lines.push('#   1. 服务器已加载 mod_headers：');
  lines.push('#      Debian/Ubuntu：a2enmod headers && systemctl reload apache2');
  lines.push('#      或主配置里：LoadModule headers_module modules/mod_headers.so');
  lines.push('#   2. 该目录允许用 .htaccess 覆盖配置：主配置里 AllowOverride FileInfo');
  lines.push('#      （Header 指令的 Override 类别是 FileInfo，只给 AuthConfig/Options 之类不会生效）');
  lines.push('#');
  lines.push('# 为什么用 `Header always set` 而不是 `Header set`：');
  lines.push('#   `Header set` 只作用于成功响应（2xx），404/500 错误页会丢掉全部这些头 ——');
  lines.push('#   而错误页同样是浏览器会渲染的 HTML，可以被打框架、被嗅探。本策略要求"每个响应都带"。');
  lines.push('#   代价：always 也会作用到 3xx/4xx/5xx 上；若应用自己也设置同名头，请保持取值一致。');
  lines.push('#');
  lines.push('# 关于 <IfModule> 守卫：mod_headers 未加载时，没有守卫会让整个目录 500 报错，');
  lines.push('# 有守卫则退化为"静默不生效"。这里选可用性优先 —— 因此部署后必须复验：');
  lines.push('#   node src/index.mjs verify --policy headers.policy.json');
  lines.push('');

  lines.push('<IfModule mod_headers.c>');

  for (const header of Object.values(policy.headers)) {
    /* 第二道注入防护：策略层已拒绝含换行/制表的值，这里再断言一次 ——
       绕过策略层直接调用生成器时，也必须拒绝而不是渲染出可注入的配置。 */
    if (INJECTION_RE.test(String(header.value))) {
      throw new Error(
        `${header.name} 的 value 含换行/制表等字符 —— 会被注入进 .htaccess 的指令语法，拒绝渲染`
      );
    }
    lines.push(`  Header always set ${header.name} "${escapeApacheValue(header.value)}"`);
  }

  /* remove 列表：策略层没有校验它，所以这里逐个过 token 规则 ——
     直接渲染 `Header always unset ${名字}` 的话，一个换行就能注入任意指令。 */
  const unsetNames = [];
  for (const name of policy.remove || []) {
    if (!TOKEN_RE.test(String(name))) {
      throw new Error(
        `remove 里的「${String(name).replace(/[\r\n\t\0]/g, '␍')}」不是合法的响应头名 —— ` +
          '会被注入进 .htaccess 的指令语法，拒绝渲染'
      );
    }
    unsetNames.push(String(name));
  }

  if (unsetNames.length) {
    lines.push('');
    lines.push('  # 删除响应头（策略里的 remove 列表）');
    lines.push('  # 注意：由 core 生成的 Server 头在部分配置下不会被 unset 掉，');
    lines.push('  # 更可靠的做法是主配置里的 ServerTokens / ServerSignature（本文件影响不到主配置）。');
    for (const name of unsetNames) lines.push(`  Header always unset ${name}`);
  }

  lines.push('</IfModule>');
  lines.push('');

  return {
    id,
    label,
    filename,
    content: lines.join('\n'),
    notes: [
      '需要站点允许覆盖：主配置 AllowOverride FileInfo（Header 指令的 Override 类别），且已加载 mod_headers',
      'mod_headers 缺失时 <IfModule> 守卫会静默跳过整块配置 —— 部署后必须用 verify 确认真生效',
      '全部使用 Header always set：错误响应（4xx/5xx）也带这些头；Header set 只覆盖 2xx',
      '.htaccess 是文件级配置：它只作用于所在目录及其子目录，换目录要重新放置',
    ],
  };
}

/**
 * 解析 `.htaccess` 里的 `Header` 指令
 *
 * 用途与 `parseHeadersFile` 对称：反向导入靠它，本地模拟器靠它把「生成的配置文件」
 * 变成真实响应头 —— 从而证明产物本身有效，而不是只验证策略对象。
 *
 * 支持：`Header [always|onsuccess] set|setifempty|add|addifempty|append|merge|unset|unsetifempty`。
 * 不解析的：`echo` / `edit` / `note`（它们是"变换/记录"而不是静态赋值，策略模型表达不了），
 * 这些行进 skipped，不静默丢弃。
 *
 * @param {string} text
 * @returns {{headers: Record<string,string>, remove: string[], skipped: Array<{where:string,line:string}>,
 *            warnings: string[], scopes: string[], directives: number}}
 */
export function parseApacheHtaccess(text) {
  const headers = {};
  const remove = [];
  const skipped = [];
  const warnings = [];
  const scopes = new Set();
  let directives = 0;

  for (const rawLine of String(text ?? '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    /* 结构块。`<IfModule ...>`（含本生成器的 `<IfModule mod_headers.c>` 外壳与它的闭合标签）
       只做"模块是否加载"的条件判断，**不改变作用范围**，所以不算"表达不了的结构"；
       其它块（<FilesMatch> / <Directory> / <Location>）会按路径/文件限定作用范围，
       那层信息在策略模型里表达不了，记入 scopes 由上层给出警告。 */
    const block = line.match(/^<\s*\/?\s*([A-Za-z][A-Za-z0-9_]*)/);
    if (block) {
      if (!/^ifmodule$/i.test(block[1])) scopes.add(block[1]);
      continue;
    }

    const match = line.match(
      /^Header\s+((?:always|onsuccess)\s+)?([A-Za-z][A-Za-z0-9*]*)\s+([A-Za-z0-9_-]+)(?:\s+(.*))?$/i
    );
    if (!match) {
      skipped.push({ where: '指令', line });
      continue;
    }

    const verb = match[2].toLowerCase();
    const name = canonicalHeaderName(match[3]);
    const rest = match[4] ?? '';
    directives += 1;

    if (UNSET_VERBS.has(verb)) {
      /* unset 之后允许跟 early / env=... 这类 Apache 参数，它们不是头名 */
      if (!remove.includes(name)) remove.push(name);
      continue;
    }

    if (SET_VERBS.has(verb)) {
      const value = readApacheArg(rest);
      if (headers[name] !== undefined && headers[name] !== value) {
        warnings.push(
          `${name} 在文件里出现了多个取值：保留后出现的「${value}」，丢弃「${headers[name]}」\n` +
            '      策略模型里一个头只能有一个取值；<FilesMatch> 之类的分路径配置请拆成多份策略'
        );
      }
      if (verb !== 'set' && verb !== 'setifempty') {
        warnings.push(
          `${name} 用的是 Header ${verb} —— 语义是"追加/合并"而不是"替换"；` +
            '策略模型只保留一个取值，重新生成时会被写成 set（替换语义），请确认这符合预期'
        );
      }
      headers[name] = value;
      continue;
    }

    skipped.push({ where: `Header ${verb}`, line });
  }

  return { headers, remove, skipped, warnings, scopes: [...scopes], directives };
}
