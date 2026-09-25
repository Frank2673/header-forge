/**
 * 单元测试：反向导入
 *
 * 验收标准是**往返一致**：generate 出来的配置，import 回去必须得到同一组
 * 「名字 → 取值」。所以这里的主力测试不是"能不能解析"，而是拿真实生成器
 * 产出四种格式，再逐一导入回来比对 —— 任何转义/格式细节上的不对称都会暴露。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validatePolicy, collectPolicyProblems } from '../src/lib/policy.mjs';
import { generateAll } from '../src/generators/index.mjs';
import {
  detectFormat,
  importConfig,
  buildPolicyDraft,
  analyzeImport,
  unescapeQuoted,
  IMPORT_FORMATS,
} from '../src/importer.mjs';

/**
 * 一份满足基线的测试策略
 *
 * 特意包含：
 *   - Link 头，取值里有双引号（`rel="preload"`）→ 逼出 nginx / caddy 的转义路径
 *   - remove 条目 → 验证 Caddy 的 -Name 删除指令能往返
 */
const TEST_POLICY_OBJECT = {
  version: 1,
  targets: { 'example.com': { primary: true } },
  headers: {
    'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains', severity: 'high' },
    'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'", severity: 'high' },
    'X-Content-Type-Options': { value: 'nosniff' },
    'Referrer-Policy': { value: 'strict-origin-when-cross-origin' },
    Link: { value: '<https://cdn.example.com>; rel="preload"; as="script"', why: '双引号转义用例' },
  },
  remove: ['X-Powered-By'],
};

function testPolicy() {
  return validatePolicy(JSON.parse(JSON.stringify(TEST_POLICY_OBJECT)));
}

/** 原始策略的「名字 → 取值」 */
function expectedMap(policy) {
  const out = {};
  for (const h of Object.values(policy.headers)) out[h.name] = h.value;
  return out;
}

/* ------------------------- 格式识别 ------------------------- */

test('按文件名识别格式', () => {
  assert.equal(detectFormat('', 'public/_headers'), 'headers');
  assert.equal(detectFormat('', 'vercel.json'), 'vercel');
  assert.equal(detectFormat('', 'nginx-security-headers.conf'), 'nginx');
  assert.equal(detectFormat('', 'Caddyfile.headers'), 'caddy');
});

test('按内容识别格式（文件名不可靠时）', () => {
  assert.equal(detectFormat('{\n  "headers": [{"source": "/(.*)", "headers": []}]\n}'), 'vercel');
  assert.equal(detectFormat('add_header X-Content-Type-Options "nosniff" always;'), 'nginx');
  assert.equal(detectFormat('example.com {\n\theader {\n\t\tX-Frame-Options "DENY"\n\t}\n}'), 'caddy');
  assert.equal(detectFormat('/*\n  X-Frame-Options: DENY\n'), 'headers');
});

test('识别不出格式时返回 null，由调用方明确报错', () => {
  assert.equal(detectFormat(''), null);
  assert.equal(detectFormat('随便一段文字'), null);
});

test('importConfig 在格式无法识别时给出可操作的错误', () => {
  const r = importConfig('随便一段文字');
  assert.equal(r.ok, false);
  assert.match(r.error, /无法识别配置格式/);
  assert.match(r.error, /--format/);
});

test('指定了不支持的格式时报错并列出可选值', () => {
  const r = importConfig('x', { format: 'apache' });
  assert.equal(r.ok, false);
  assert.match(r.error, /不支持的格式：apache/);
  assert.match(r.error, new RegExp(IMPORT_FORMATS.join(' / ')));
});

/* ------------------------- 往返一致（核心） ------------------------- */

test('**五种格式往返全部一致**（含双引号转义）', () => {
  const policy = testPolicy();
  const expected = expectedMap(policy);
  const artifacts = generateAll(policy);

  assert.equal(artifacts.length, 6, '六个平台产物');

  /* 逐个产物导入回来比对名字与取值。
     这里显式 include: 'all' —— 往返测的是"生成器与解析器严格对称"，
     默认的安全类过滤是产品层面的取舍，不该掺进这条不变式。 */
  for (const artifact of artifacts) {
    /* cloudflare-pages 与 netlify 都是 _headers 格式，用同一个解析器 */
    const format = artifact.id === 'vercel' ? 'vercel'
      : artifact.id === 'nginx' ? 'nginx'
      : artifact.id === 'caddy' ? 'caddy'
      : artifact.id === 'htaccess' ? 'htaccess'
      : 'headers';

    const r = importConfig(artifact.content, { format, filename: artifact.filename, include: 'all' });
    assert.equal(r.ok, true, `${artifact.id} 导入失败：${r.error}`);

    assert.deepEqual(
      Object.keys(r.headers).sort(),
      Object.keys(expected).sort(),
      `${artifact.id} 的名字集合应一致`
    );
    for (const [name, value] of Object.entries(expected)) {
      assert.equal(r.headers[name], value, `${artifact.id} 的 ${name} 取值应往返一致`);
    }
  }
});

test('Caddy 的 -Name 删除指令能往返', () => {
  const policy = testPolicy();
  const caddy = generateAll(policy, { only: ['caddy'] })[0];
  assert.match(caddy.content, /-X-Powered-By/, '生成器应写出删除指令');

  const r = importConfig(caddy.content, { format: 'caddy' });
  assert.deepEqual(r.remove, ['X-Powered-By']);
});

test('unescapeQuoted 逆转 \\" 与 \\\\，且不重复反转义', () => {
  assert.equal(unescapeQuoted('a\\"b'), 'a"b');
  assert.equal(unescapeQuoted('a\\\\b'), 'a\\b');
  /* 已经是转义后的反斜杠+引号：应还原成 反斜杠+引号，而不是 引号 */
  assert.equal(unescapeQuoted('a\\\\\\"b'), 'a\\"b');
  assert.equal(unescapeQuoted('普通文本'), '普通文本');
});

/* ------------------------- 各格式解析细节 ------------------------- */

test('_headers：注释与空行被忽略，多路径块合并并给出警告', () => {
  const text = [
    '# 注释',
    '/*',
    '  X-Frame-Options: DENY',
    '',
    '/api/*',
    '  X-Frame-Options: SAMEORIGIN',
  ].join('\n');

  const r = importConfig(text, { format: 'headers' });
  assert.equal(r.ok, true);
  assert.equal(r.headers['X-Frame-Options'], 'SAMEORIGIN', '后出现的覆盖先出现的');
  assert.ok(r.warnings.some((w) => w.includes('2 个路径块')));
});

test('nginx：解析带引号/不带引号/无 always 三种写法', () => {
  const text = [
    'add_header X-Frame-Options "DENY" always;',
    "add_header Referrer-Policy no-referrer;",
    'add_header X-Content-Type-Options "nosniff";',
  ].join('\n');

  const r = importConfig(text, { format: 'nginx' });
  assert.equal(r.ok, true);
  assert.equal(r.headers['X-Frame-Options'], 'DENY');
  assert.equal(r.headers['Referrer-Policy'], 'no-referrer');
  assert.equal(r.headers['X-Content-Type-Options'], 'nosniff');
});

test('nginx：存在 location 块时给出结构性警告（策略模型表达不了）', () => {
  const text = [
    'add_header X-Frame-Options "DENY" always;',
    'location /api/ {',
    '  add_header X-Frame-Options "SAMEORIGIN" always;',
    '}',
  ].join('\n');

  const r = importConfig(text, { format: 'nginx' });
  assert.ok(r.warnings.some((w) => w.includes('location')));
  assert.ok(r.warnings.some((w) => w.includes('覆盖父级')));
});

test('vercel：解析 headers 数组，非 JSON 时给出可读错误', () => {
  const ok = importConfig(JSON.stringify({ headers: [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }] }), { format: 'vercel' });
  assert.equal(ok.ok, true);
  assert.equal(ok.headers['X-Frame-Options'], 'DENY');

  const bad = importConfig('{不是JSON', { format: 'vercel' });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /没有得到任何响应头|不是合法 JSON/);
  assert.ok(bad.skipped.some((s) => /不是合法 JSON/.test(s.line)), '应把 JSON 解析错误也带出来');
});

test('vercel：条目缺 key/value 时进 skipped，不静默丢弃', () => {
  const text = JSON.stringify({
    headers: [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }, { key: 'Broken' }] }],
  });

  const r = importConfig(text, { format: 'vercel' });
  assert.equal(r.ok, true);
  assert.equal(r.skipped.length, 1);
  assert.equal(r.skipped[0].where, 'headers 条目', 'where 描述位置');
  assert.match(r.skipped[0].line, /Broken/, 'line 是原文');
});

test('caddy：只认 header 块内的行，站点块里的其它指令不进结果', () => {
  const text = [
    'example.com {',
    '\theader {',
    '\t\tX-Frame-Options "DENY"',
    '\t\t-X-Powered-By',
    '\t}',
    '\tfile_server',
    '\troot * /srv',
    '}',
  ].join('\n');

  const r = importConfig(text, { format: 'caddy' });
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.headers), ['X-Frame-Options']);
  assert.ok(!('File_server' in r.headers), 'file_server 不该被当成响应头');
  assert.ok(!('Root' in r.headers), 'root 不该被当成响应头');
  assert.deepEqual(r.remove, ['X-Powered-By']);
});

test('caddy：`- Name` 带空格的删除写法也能识别（不被当成名为「-」的头）', () => {
  const text = ['example.com {', '\theader {', '\t\t- X-Powered-By', '\t}', '}'].join('\n');

  const r = importConfig(text, { format: 'caddy' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.remove, ['X-Powered-By']);
  assert.ok(!Object.keys(r.headers).includes('-'), '绝不能产出名为「-」的响应头');
});

test('caddy：header 块内的垃圾行进 skipped，不污染结果', () => {
  const text = ['example.com {', '\theader {', '\t\t这行不是响应头 也不是删除', '\t\tX-Frame-Options "DENY"', '\t}', '}'].join('\n');

  const r = importConfig(text, { format: 'caddy' });
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.headers), ['X-Frame-Options']);
  assert.equal(r.skipped.length, 1, '无法识别的行必须被记下来');
});

test('同名头取值冲突时给出警告，并保留后出现的那一个', () => {
  const text = [
    'add_header X-Frame-Options "DENY" always;',
    'add_header X-Frame-Options "SAMEORIGIN" always;',
  ].join('\n');

  const r = importConfig(text, { format: 'nginx' });
  assert.equal(r.headers['X-Frame-Options'], 'SAMEORIGIN');
  assert.ok(r.warnings.some((w) => w.includes('多个取值')));
});

test('同名头取值相同不算冲突（生成的配置里不该有噪音警告）', () => {
  const text = [
    'add_header X-Frame-Options "DENY" always;',
    'add_header X-Frame-Options "DENY" always;',
  ].join('\n');

  const r = importConfig(text, { format: 'nginx' });
  assert.deepEqual(r.warnings, []);
});

test('解析不到任何头时判为失败，而不是产出一份空策略', () => {
  const r = importConfig('# 只有注释\n', { format: 'headers' });
  assert.equal(r.ok, false);
  assert.match(r.error, /没有.*任何响应头|没有解析出任何路径块/);
});

/* ------------------------- 忠实反映现状（不自动补齐） ------------------------- */

test('**导入弱配置时不自动补齐缺失的头** —— 差距要暴露而不是掩盖', () => {
  const weak = [
    '/*',
    '  X-Frame-Options: DENY',
    '  X-Content-Type-Options: nosniff',
  ].join('\n');

  const r = analyzeImport(weak, { format: 'headers' });
  assert.equal(r.ok, true);

  /* 策略里只有配置里真实存在的两个头 */
  assert.deepEqual(Object.keys(r.draft.headers).sort(), ['X-Content-Type-Options', 'X-Frame-Options']);

  /* 缺失的基线头以"差距"形式报出来，而不是被补进策略 */
  assert.ok(r.gaps.some((g) => g.includes('Strict-Transport-Security')));
  assert.ok(r.gaps.some((g) => g.includes('Content-Security-Policy')));
  assert.ok(r.gaps.some((g) => g.includes('Referrer-Policy')));
  assert.ok(!('Strict-Transport-Security' in r.draft.headers), '绝不能替用户造出这个头');
});

test('导入过弱的 HSTS 时报出 max-age 差距', () => {
  const weak = '/*\n  Strict-Transport-Security: max-age=3600\n';
  const r = analyzeImport(weak, { format: 'headers' });

  assert.equal(r.draft.headers['Strict-Transport-Security'].value, 'max-age=3600', '原值必须保留');
  assert.ok(r.gaps.some((g) => g.includes('max-age 过短')));
});

test('导入含 unsafe-inline 的 CSP 时如实报出（不静默接受）', () => {
  const weak = "/*\n  Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'\n";
  const r = analyzeImport(weak, { format: 'headers' });

  assert.ok(r.gaps.some((g) => g.includes('unsafe-inline')));
});

test('现状满足基线时 gaps 为空', () => {
  const good = [
    '/*',
    '  Strict-Transport-Security: max-age=31536000; includeSubDomains',
    "  Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
    '  X-Content-Type-Options: nosniff',
    '  Referrer-Policy: strict-origin-when-cross-origin',
  ].join('\n');

  const r = analyzeImport(good, { format: 'headers' });
  assert.deepEqual(r.gaps, []);
});

/* ------------------------- 导入范围：默认只接管安全类 ------------------------- */

test('默认只导入安全响应头，非安全头进 ignored 并说明原因', () => {
  const text = [
    '/*',
    '  X-Frame-Options: DENY',
    '  Cache-Control: public, max-age=3600',
    '  Access-Control-Allow-Origin: *',
    '  Content-Type: text/html; charset=utf-8',
  ].join('\n');

  const r = importConfig(text, { format: 'headers' });
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.headers), ['X-Frame-Options']);

  assert.deepEqual(
    r.ignored.map((i) => i.name).sort(),
    ['Access-Control-Allow-Origin', 'Cache-Control', 'Content-Type']
  );
  for (const i of r.ignored) assert.match(i.reason, /不属于安全响应头/);
});

test('include: all 时全量导入', () => {
  const text = '/*\n  X-Frame-Options: DENY\n  Cache-Control: no-store\n';
  const r = importConfig(text, { format: 'headers', include: 'all' });

  assert.deepEqual(Object.keys(r.headers).sort(), ['Cache-Control', 'X-Frame-Options']);
  assert.deepEqual(r.ignored, []);
});

test('文件里只有非安全头时明确报错并给出 --all 的出路', () => {
  const r = importConfig('/*\n  Cache-Control: no-store\n', { format: 'headers' });

  assert.equal(r.ok, false);
  assert.match(r.error, /都不是安全响应头/);
  assert.match(r.error, /Cache-Control/);
  assert.match(r.error, /--all/);
  assert.equal(r.ignored.length, 1);
});

test('**非安全头的按路径冲突不产生噪音警告**（真实世界的主要形态）', () => {
  /* 这是抓了 9 份公开仓库配置后发现的形态：Cache-Control 按路径分别取值。
     我们根本不导入 Cache-Control，所以不该为它报冲突 —— 那会淹没真正的问题。 */
  const text = [
    '/*',
    '  Cache-Control: public, max-age=0, must-revalidate',
    '  X-Frame-Options: DENY',
    '/fonts/*',
    '  Cache-Control: public, max-age=31536000, immutable',
    '/img/*',
    '  Cache-Control: public, max-age=86400, immutable',
  ].join('\n');

  const r = importConfig(text, { format: 'headers' });
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.headers), ['X-Frame-Options']);
  assert.deepEqual(r.warnings, [], '不该为不导入的头报冲突');

  /* 同一个文件用 include: all 导入时，冲突就必须报出来 */
  const all = importConfig(text, { format: 'headers', include: 'all' });
  assert.ok(all.warnings.some((w) => w.includes('Cache-Control 出现了多个取值')));
});

test('安全头确实按路径冲突时仍然报警（不因为过滤而漏掉真问题）', () => {
  const text = ['/*', '  X-Frame-Options: DENY', '/api/*', '  X-Frame-Options: SAMEORIGIN'].join('\n');

  const r = importConfig(text, { format: 'headers' });
  assert.equal(r.headers['X-Frame-Options'], 'SAMEORIGIN');
  assert.ok(r.warnings.some((w) => w.includes('X-Frame-Options 出现了多个取值')));
  assert.ok(r.warnings.some((w) => w.includes('按路径不同')), '应指出是路径差异导致的');
});

test('路径块多但安全头取值一致时不报结构警告（多数真实配置是这个样子）', () => {
  const text = ['/*', '  X-Frame-Options: DENY', '/api/*', '  X-Frame-Options: DENY'].join('\n');
  const r = importConfig(text, { format: 'headers' });

  assert.deepEqual(r.warnings, [], '重复声明同一个值不是问题，不该报警');
});

/* ------------------------- 策略草稿 ------------------------- */

test('草稿里的 why 是占位说明，明确标注"尚未人工确认"', () => {
  const r = analyzeImport('/*\n  X-Frame-Options: DENY\n', { format: 'headers' });

  for (const spec of Object.values(r.draft.headers)) {
    assert.match(spec.why, /导入/);
    assert.match(spec.why, /尚未人工确认/);
    assert.equal(spec.severity, 'info');
  }
});

test('草稿能直接通过 JSON 往返，结构符合策略 schema', () => {
  const r = analyzeImport('/*\n  X-Frame-Options: DENY\n', { format: 'headers' });
  const cloned = JSON.parse(JSON.stringify(r.draft));

  assert.equal(cloned.version, 1);
  assert.equal(typeof cloned.headers, 'object');
  assert.equal(cloned.headers['X-Frame-Options'].value, 'DENY');
});

test('buildPolicyDraft 在无删除指令时不写 remove 字段', () => {
  const draft = buildPolicyDraft({ headers: { 'X-Frame-Options': 'DENY' }, remove: [] });
  assert.equal('remove' in draft, false);
});

test('导入的草稿可以被基线校验器消费（不抛异常）', () => {
  const r = analyzeImport('/*\n  X-Frame-Options: DENY\n', { format: 'headers' });
  /* collectPolicyProblems 对结构合法的对象只返回 problems，不抛 */
  const { problems } = collectPolicyProblems(r.draft);
  assert.ok(Array.isArray(problems));
  assert.ok(problems.length > 0, '弱配置应当有问题');
});

test('导入结果不受头名大小写影响（统一规范化）', () => {
  const r = importConfig('/*\n  x-frame-options: DENY\n  X-CONTENT-TYPE-OPTIONS: nosniff\n', { format: 'headers' });
  assert.ok('X-Frame-Options' in r.headers);
  assert.ok('X-Content-Type-Options' in r.headers);
});
