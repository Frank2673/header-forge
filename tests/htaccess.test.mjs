/**
 * Apache `.htaccess` 生成器测试
 *
 * 重点（与其它生成器相比多出来的两处风险）：
 *   1. **前置条件**：`.htaccess` 不生效时是无声的（mod_headers 缺失 + IfModule 守卫
 *      → 静默跳过；AllowOverride 不含 FileInfo → 整块不生效）。所以产物必须自带说明，
 *      且守卫的存在要在注释里写清代价。
 *   2. **注入面比 nginx/caddy 多一个**：策略层的注入防护只校验 `headers[*].value`，
 *      **不校验 `remove` 数组**（`lib/policy.mjs` 对 remove 只做 Array 判断）。
 *      所以这里既测"值带换行被拒"，也测"remove 项带换行被生成器拒"。
 *
 * 加上与其它格式一致的往返一致性：generate → import 必须得到同一组名字与取值。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generate,
  parseApacheHtaccess,
  escapeApacheValue,
  unescapeApacheValue,
  readApacheArg,
} from '../src/generators/htaccess.mjs';
import { escapeNginxValue } from '../src/generators/nginx.mjs';
import { generateAll, planOutputPaths } from '../src/generators/index.mjs';
import { importConfig, detectFormat, unescapeQuoted } from '../src/importer.mjs';
import { parseGeneratedConfig, startSimulator } from '../src/simulate.mjs';
import { validatePolicy } from '../src/lib/policy.mjs';
import { verifyUrl } from '../src/verify.mjs';

/** 一份满足基线的最小策略 */
function baselinePolicy(extra = {}) {
  return validatePolicy({
    version: 1,
    headers: {
      'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains' },
      'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'" },
      'X-Content-Type-Options': { value: 'nosniff' },
      'Referrer-Policy': { value: 'strict-origin-when-cross-origin' },
      ...extra,
    },
    remove: ['X-Powered-By'],
  });
}

const htaccessOf = (policy) => generateAll(policy, { only: ['htaccess'] })[0];

/* ---------------------------- 渲染 ---------------------------- */

test('产物带 <IfModule mod_headers.c> 守卫，且指令用 Header always set', () => {
  const artifact = htaccessOf(baselinePolicy());

  assert.ok(artifact.content.includes('<IfModule mod_headers.c>'), '缺少 mod_headers 守卫');
  assert.ok(artifact.content.includes('</IfModule>'));
  assert.ok(
    artifact.content.includes('  Header always set X-Content-Type-Options "nosniff"'),
    '应为缩进的 Header always set 指令、值用双引号包裹'
  );
  assert.match(artifact.content, /Header always unset X-Powered-By$/m, 'remove 列表应渲染成 unset');
  assert.equal(artifact.filename, '.htaccess');
});

test('守卫与 always 的取舍必须写进产物（不生效是无声的，得先告诉用户）', () => {
  const { content } = htaccessOf(baselinePolicy());

  assert.match(content, /AllowOverride FileInfo/, '必须写明 AllowOverride 的前置条件');
  assert.match(content, /mod_headers/, '必须写明 mod_headers 前置条件');
  assert.match(content, /静默不生效/, 'IfModule 守卫的代价必须写明');
  assert.match(content, /Header set.*只作用于成功响应/s, 'always 与 set 的区别必须写明');
  assert.match(content, /verify --policy/, '必须给出部署后的复验命令');
});

test('notes 覆盖部署要点（CLI 会打印）', () => {
  const artifact = htaccessOf(baselinePolicy());

  assert.ok(artifact.notes.length > 0);
  assert.ok(artifact.notes.some((n) => /AllowOverride FileInfo/.test(n)));
  assert.ok(artifact.notes.some((n) => /错误响应|4xx/.test(n)));
});

test('转义：引号与反斜杠（防配置注入），且与 nginx 同一套语义', () => {
  assert.equal(escapeApacheValue('a"b'), 'a\\"b');
  assert.equal(escapeApacheValue('a\\b'), 'a\\\\b');
  assert.equal(escapeApacheValue('a\\b"c'), 'a\\\\b\\"c');

  /* 各平台对"值里出现引号/反斜杠"必须给出同一个字面值，否则同一条策略在不同平台
     会得到不同的头 —— 这里做一次交叉核对，防止两处转义各自漂移。 */
  for (const sample of ['a"b', 'a\\b', 'a\\b"c', "default-src 'self'", 'max-age=31536000; includeSubDomains']) {
    assert.equal(escapeApacheValue(sample), escapeNginxValue(sample), `转义语义漂移：${sample}`);
  }
});

test('逆转义与逃逸互逆，且与 importer.unescapeQuoted 同语义', () => {
  for (const sample of ['a"b', 'a\\b', 'a\\\\b"c', "default-src 'self'", 'nosniff']) {
    assert.equal(unescapeApacheValue(escapeApacheValue(sample)), sample);
    assert.equal(unescapeApacheValue(sample), unescapeQuoted(sample), `逆转义语义漂移：${sample}`);
  }
});

test('readApacheArg 取引号内的值，并忽略 Apache 自己的参数', () => {
  assert.equal(readApacheArg('"nosniff"'), 'nosniff');
  assert.equal(readApacheArg("'nosniff'"), 'nosniff');
  assert.equal(readApacheArg('nosniff'), 'nosniff');
  assert.equal(readApacheArg('"max-age=31536000; includeSubDomains"'), 'max-age=31536000; includeSubDomains');
  assert.equal(readApacheArg('"DENY" early'), 'DENY', 'early 不是值的一部分');
  assert.equal(readApacheArg('DENY env=!nokeep'), 'DENY');
  assert.equal(readApacheArg(''), '');
});

/* ---------------------------- 解析 ---------------------------- */

test('生成的产物可被解析回同一组名字与取值', () => {
  const policy = baselinePolicy({ 'X-Test': { value: 'a\\b"c' } });
  const parsed = parseApacheHtaccess(htaccessOf(policy).content);

  for (const header of Object.values(policy.headers)) {
    assert.equal(parsed.headers[header.name], header.value, `${header.name} 取值应往返一致`);
  }
  assert.deepEqual(parsed.remove, ['X-Powered-By']);
  assert.equal(parsed.directives, 6);
});

test('手写形式也认：Header set / onsuccess / 单引号 / 无引号', () => {
  const parsed = parseApacheHtaccess(
    [
      '<IfModule mod_headers.c>',
      '  Header set X-A "1"',
      "  Header always set X-B '2'",
      '  Header onsuccess set X-C 3',
      '  Header always unset X-D',
      '</IfModule>',
    ].join('\n')
  );

  assert.equal(parsed.headers['X-A'], '1');
  assert.equal(parsed.headers['X-B'], '2');
  assert.equal(parsed.headers['X-C'], '3');
  assert.deepEqual(parsed.remove, ['X-D']);
  /* `<IfModule mod_headers.c>` 是标准外壳，不该被当成"表达不了的结构"报警 */
  assert.deepEqual(parsed.scopes, []);
});

test('echo / edit / note 不是静态赋值 —— 进 skipped，不静默丢弃', () => {
  const parsed = parseApacheHtaccess(
    [
      'Header echo X-Request-Id',
      'Header edit X-Frame-Options ^DENY$ SAMEORIGIN',
      'Header note X-Log me',
      '这不是指令',
    ].join('\n')
  );

  assert.equal(parsed.directives, 3);
  assert.deepEqual(Object.keys(parsed.headers), []);
  assert.equal(parsed.skipped.length, 4);
  assert.ok(parsed.skipped.some((s) => s.where === 'Header echo'));
  assert.ok(parsed.skipped.some((s) => s.where === 'Header edit'));
});

test('分路径结构块（<FilesMatch>）记入 scopes，由导入层给出警告', () => {
  const text = [
    '<IfModule mod_headers.c>',
    '  Header always set X-A "1"',
    '</IfModule>',
    '<FilesMatch "\\.html$">',
    '  Header always set X-B "2"',
    '</FilesMatch>',
  ].join('\n');

  const parsed = parseApacheHtaccess(text);
  assert.deepEqual(parsed.scopes, ['FilesMatch']);

  const imported = importConfig(text, { format: 'htaccess', include: 'all' });
  assert.equal(imported.ok, true);
  assert.equal(imported.headers['X-B'], '2');
  assert.ok(
    imported.warnings.some((w) => /FilesMatch/.test(w) && /结构/.test(w)),
    '分路径结构必须给出警告'
  );
});

test('Header append 会提示语义差异（策略模型只留一个取值）', () => {
  const imported = importConfig('Header append Set-Cookie "a=1"', { format: 'htaccess', include: 'all' });

  assert.equal(imported.ok, true);
  assert.ok(imported.warnings.some((w) => /append/.test(w) && /替换/.test(w)));
});

test('取值冲突时报警告并保留后出现的那一个', () => {
  const imported = importConfig(
    ['Header always set X-Frame-Options "DENY"', 'Header always set X-Frame-Options "SAMEORIGIN"'].join('\n'),
    { format: 'htaccess', include: 'all' }
  );

  assert.equal(imported.headers['X-Frame-Options'], 'SAMEORIGIN');
  assert.ok(imported.warnings.some((w) => /多个取值/.test(w)));
});

/* ---------------------------- 格式识别 ---------------------------- */

test('detectFormat：文件名与内容特征都能认出 .htaccess', () => {
  const generated = htaccessOf(baselinePolicy()).content;

  assert.equal(detectFormat(generated, 'dist/.htaccess'), 'htaccess');
  assert.equal(detectFormat(generated, 'public\\.htaccess'), 'htaccess', 'Windows 路径分隔符也要认');
  assert.equal(detectFormat(generated), 'htaccess', '不给文件名时靠内容特征');
  assert.equal(detectFormat('<IfModule mod_headers.c>\n</IfModule>'), 'htaccess');
  /* 不能误判别的格式 */
  assert.equal(detectFormat('/*\n  X-A: 1\n', '_headers'), 'headers');
  assert.equal(detectFormat('add_header X-A "1" always;', 'nginx.conf'), 'nginx');
});

/* ---------------------------- 往返一致 ---------------------------- */

test('往返一致：名字与取值逐字相等（含双引号与反斜杠）', () => {
  const policy = baselinePolicy({
    Link: { value: '<https://cdn.example.com>; rel="preload"; as="script"' },
    'X-Test-Backslash': { value: 'a\\b"c' },
  });

  const artifact = htaccessOf(policy);
  const imported = importConfig(artifact.content, { format: 'htaccess', filename: artifact.filename, include: 'all' });

  assert.equal(imported.ok, true, `导入失败：${imported.error}`);
  for (const header of Object.values(policy.headers)) {
    assert.equal(imported.headers[header.name], header.value, `${header.name} 应往返一致`);
  }
  assert.deepEqual(imported.remove, ['X-Powered-By']);
});

test('相同策略重复生成结果完全一致（可复现）', () => {
  const policy = baselinePolicy();
  assert.equal(generate(policy).content, generate(policy).content);
});

test('落点：.htaccess 落在发布目录根下（进子目录就只对子路径生效）', () => {
  const planned = planOutputPaths('dist', generateAll(baselinePolicy()));

  const entry = planned.find((p) => p.artifact.id === 'htaccess');
  assert.equal(entry.target, 'dist/.htaccess', '.htaccess 必须与 index.html 同级');
  assert.equal(entry.disambiguated, false, '它与 _headers 不撞名，不该被消歧逻辑挪走');

  const targets = planned.map((p) => p.target);
  assert.equal(new Set(targets).size, targets.length, `落点有重复：${targets.join(', ')}`);
});

/* ------------------------- 注入防护（三道） ------------------------- */

test('第一道：策略值含换行 → 策略层拒绝（与其它平台同一条路径）', () => {
  assert.throws(
    () =>
      validatePolicy({
        version: 1,
        headers: {
          'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains' },
          'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'" },
          'X-Content-Type-Options': { value: 'nosniff' },
          'Referrer-Policy': { value: 'strict-origin-when-cross-origin' },
          /* 注意用的是 htaccess 语法：闭合 IfModule 后注入任意指令 */
          'X-Evil': { value: '1\n</IfModule>\nHeader always set X-Injected: yes' },
        },
      }),
    /会被注入进生成的配置语法/
  );
});

test('第二道：绕过策略层直接调用生成器，值含换行同样被拒（不是死代码）', () => {
  const raw = {
    headers: { 'X-Evil': { name: 'X-Evil', value: '1\n</IfModule>\nHeader always set X-Injected: yes' } },
  };

  assert.throws(() => generate(raw), /会被注入进 \.htaccess 的指令语法，拒绝渲染/);
});

test('第三道：remove 项含换行也被拒 —— 策略层不校验这个字段', () => {
  const raw = {
    headers: { 'X-Content-Type-Options': { name: 'X-Content-Type-Options', value: 'nosniff' } },
    /* lib/policy.mjs 对 remove 只做 Array.isArray 判断，不校验条目 —— 直接渲染就是注入 */
    remove: ['X-Powered-By\n</IfModule>\nHeader always set X-Injected: yes'],
  };

  assert.throws(() => generate(raw), /remove 里的.*不是合法的响应头名/);
});

test('策略层的 remove 校验缺口是真实可达的（本生成器拒绝，但解析层放行）', () => {
  /* 记录这条缺口的可复现证据：loadPolicy 对这样的 remove 不报错，
     因此"直接渲染 remove 的生成器"会成为注入面 —— 本生成器已自行拦截。 */
  const policy = validatePolicy({
    version: 1,
    headers: {
      'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains' },
      'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'" },
      'X-Content-Type-Options': { value: 'nosniff' },
      'Referrer-Policy': { value: 'strict-origin-when-cross-origin' },
    },
    remove: ['X-A\nHeader always set X-Injected "1"'],
  });

  assert.equal(policy.remove.length, 1, '策略层确实没有拦住这一项');
  assert.throws(() => generate(policy), /拒绝渲染/, '生成器必须自己拦住');
});

/* ------------------------- 模拟器接入 ------------------------- */

test('模拟器能从 .htaccess 产物解析响应头（整块作用于目录，无路径模式）', () => {
  const policy = baselinePolicy();
  const headers = parseGeneratedConfig(htaccessOf(policy).content);

  assert.equal(headers['X-Content-Type-Options'], 'nosniff');
  assert.equal(headers['Content-Security-Policy'], policy.headers['Content-Security-Policy'].value);
  assert.equal(Object.keys(headers).length, Object.keys(policy.headers).length);
  assert.equal(headers['X-Powered-By'], undefined, '被 unset 的头不应出现在解析结果里');
});

test('端到端：用 .htaccess 产物起服务，校验器判定完全符合策略', async () => {
  const policy = baselinePolicy();
  const sim = await startSimulator({ configText: htaccessOf(policy).content });

  try {
    const result = await verifyUrl(policy, sim.url);
    assert.equal(result.ok, true, `请求失败：${result.error}`);

    const problems = result.results.filter((r) => r.status === 'missing' || r.status === 'mismatch');
    assert.deepEqual(problems, [], `存在不符合项：${JSON.stringify(problems, null, 2)}`);
    assert.equal(result.results.filter((r) => r.status === 'pass').length, Object.keys(policy.headers).length);
  } finally {
    await sim.close();
  }
});

test('端到端负向验证：产物里少一个头会被如实暴露（证明校验不是走过场）', () => {
  const policy = baselinePolicy();
  const tampered = htaccessOf(policy)
    .content.split('\n')
    .filter((line) => !line.includes('Referrer-Policy'))
    .join('\n');

  const headers = parseGeneratedConfig(tampered);
  assert.equal(headers['Referrer-Policy'], undefined);
  assert.equal(Object.keys(headers).length, Object.keys(policy.headers).length - 1);
});
