/**
 * `policy.remove` 的注入防护 —— 回归测试
 *
 * 背景（已确认的低危缺陷）：策略层的配置注入防护原本只覆盖 `headers.*.value`，
 * 漏掉了 `remove` 数组。而 `remove` 也会被渲染进配置语法：
 *
 *   caddy    →  `-${name}`（裸渲染，不需要转义就能逃逸）
 *   htaccess →  `Header always unset ${name}`
 *
 * 于是 `remove: ["X-Powered-By\r\n\t}\r\n\trespond \"...\" 200\r\n\theader {"]`
 * 会关掉 caddy 的 header 块并注入一条任意指令 ——
 * `node src/index.mjs generate --only caddy` 退出码 0、注入指令直接落盘。
 *
 * 本文件把三层都钉死：
 *   1. 策略层拒绝（第一道关，覆盖所有渲染点）
 *   2. 各生成器绕过策略层直接调用时也拒绝（第二道关，按渲染点逐个覆盖）
 *   3. 非法 remove 下全量 generate 不落盘任何文件
 */

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validatePolicy, collectPolicyProblems, isSafeHeaderName, PolicyError } from '../src/lib/policy.mjs';
import { generateAll, planOutputPaths } from '../src/generators/index.mjs';
import * as caddy from '../src/generators/caddy.mjs';
import * as nginx from '../src/generators/nginx.mjs';
import * as htaccess from '../src/generators/htaccess.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_ROOT = join(REPO, 'tmp', 'policy-remove-injection', 'test-out');

after(() => {
  rmSync(join(REPO, 'tmp', 'policy-remove-injection'), { recursive: true, force: true });
});

let caseNo = 0;
function tmpDir(name) {
  const p = join(OUT_ROOT, `${name}-${process.pid}-${++caseNo}`);
  mkdirSync(p, { recursive: true });
  return p;
}

/**
 * 注入载荷：先关掉 header 块，再写一条策略里没有的 respond 指令，最后把块重新打开。
 * 这样生成的 Caddyfile 语法依然完整，但多出一条攻击者可控的指令。
 */
const CADDY_INJECTION = 'X-Powered-By\r\n\t}\r\n\trespond "INJECTED-BY-POLICY" 200\r\n\theader {';

/** 一份最小合规策略 */
function basePolicy(overrides = {}) {
  return {
    version: 1,
    headers: {
      'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains', severity: 'medium' },
      'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'", severity: 'medium' },
      'X-Content-Type-Options': { value: 'nosniff', severity: 'low' },
      'Referrer-Policy': { value: 'strict-origin-when-cross-origin', severity: 'low' },
    },
    ...overrides,
  };
}

/* ------------------------------------------------------------------ *
 * 1. 策略层：第一道关
 * ------------------------------------------------------------------ */

test('remove 含换行（可逃逸出配置语法）被策略层拒绝', () => {
  assert.throws(
    () => validatePolicy(basePolicy({ remove: [CADDY_INJECTION] })),
    (err) => {
      assert.ok(err instanceof PolicyError, '应抛 PolicyError');
      assert.match(err.message, /remove 里的/);
      assert.match(err.message, /会被注入进生成的配置语法/);
      return true;
    }
  );
});

test('remove 含制表符 / NUL 同样被拒绝', () => {
  assert.throws(() => validatePolicy(basePolicy({ remove: ['X-Powered-By\tx'] })), PolicyError);
  assert.throws(() => validatePolicy(basePolicy({ remove: ['X-Powered-By\0'] })), PolicyError);
});

test('remove 含空白与可逃逸字符一律被拒绝', () => {
  for (const bad of [
    'X-Powered-By ',       // 行尾空格
    ' X-Powered-By',       // 行首空格
    'X Powered By',        // 内部空格
    'X-Powered-By}',       // 能关掉块的花括号
    'X-Powered-By"',       // 能截断引号串
    'X-Powered-By;set x',  // 分号 + 指令
    'X-Powered-By:',       // 冒号（响应头行分隔符）
    'X-Powered-By\\',      // 转义字符
    '',                    // 空名
  ]) {
    assert.throws(
      () => validatePolicy(basePolicy({ remove: [bad] })),
      PolicyError,
      `应拒绝 remove 条目：${JSON.stringify(bad)}`
    );
  }
});

test('remove 必须是非空名字组成的数组（非数组 / 非字符串项都拒绝）', () => {
  assert.throws(() => validatePolicy(basePolicy({ remove: 'X-Powered-By' })), /remove 必须是数组/);
  assert.throws(() => validatePolicy(basePolicy({ remove: [null] })), PolicyError);
  assert.throws(() => validatePolicy(basePolicy({ remove: [42] })), PolicyError);
  assert.throws(() => validatePolicy(basePolicy({ remove: [{ name: 'X' }] })), PolicyError);
});

test('合法的 remove 原样通过校验（顺序不变、去重）', () => {
  const policy = validatePolicy(basePolicy({ remove: ['X-Powered-By', 'Server', 'X-Powered-By'] }));
  assert.deepEqual(policy.remove, ['X-Powered-By', 'Server']);
});

test('未声明 remove 时退化为空数组', () => {
  assert.deepEqual(validatePolicy(basePolicy()).remove, []);
});

test('collectPolicyProblems 也把非法 remove 记入 problems（导入路径同样能看见这个差距）', () => {
  const { problems, remove } = collectPolicyProblems(basePolicy({ remove: [CADDY_INJECTION, 'Server'] }));
  assert.equal(problems.length, 1);
  assert.match(problems[0], /remove 里的/);
  assert.deepEqual(remove, ['Server'], '非法项被剔除，合法项保留');
});

test('isSafeHeaderName 的判据 = RFC 7230 token', () => {
  assert.equal(isSafeHeaderName('X-Powered-By'), true);
  assert.equal(isSafeHeaderName('X_Content_Type~Opts'), true);
  /* `#` 本身是合法 token 字符（不构成注入：没有换行就逃不出这一行） */
  assert.equal(isSafeHeaderName('X-Powered-By#x'), true);
  assert.equal(isSafeHeaderName('X-Powered-By\n'), false);
  assert.equal(isSafeHeaderName(''), false);
  assert.equal(isSafeHeaderName(null), false);
  assert.equal(isSafeHeaderName(undefined), false);
});

/* ------------------------------------------------------------------ *
 * 2. 生成器层：第二道关（绕过策略层直接调用）
 * ------------------------------------------------------------------ */

/** 手工构造一份"绕过策略层"的策略对象（loadPolicy 不会放行，但生成器 API 是公开的） */
function unvalidatedPolicy(remove) {
  const { headers } = validatePolicy(basePolicy());
  return { version: 1, targets: {}, headers, remove };
}

test('caddy：绕过策略层直接渲染时，非法 remove 被生成器拒绝（不产出可注入的 Caddyfile）', () => {
  const policy = unvalidatedPolicy([CADDY_INJECTION]);
  assert.throws(
    () => caddy.generate(policy, { siteAddress: 'example.com' }),
    /会被注入进 Caddyfile 的指令语法/
  );
});

test('caddy：非法 remove 不会出现在产物里（正面对照：同一载荷修复前会落进 Caddyfile）', () => {
  const policy = unvalidatedPolicy([CADDY_INJECTION]);
  let content = null;
  try {
    content = caddy.generate(policy, { siteAddress: 'example.com' }).content;
  } catch {
    content = null;
  }
  assert.equal(content, null, '必须抛错而不是渲染出内容');
});

test('caddy：合法 remove 仍正常渲染为 -Name', () => {
  const policy = unvalidatedPolicy(['X-Powered-By', 'Server']);
  const out = caddy.generate(policy, { siteAddress: 'example.com' }).content;
  assert.match(out, /^\t\t-X-Powered-By$/m);
  assert.match(out, /^\t\t-Server$/m);
  assert.match(out, /\t\}\n\tfile_server/, 'header 块结构未被破坏');
});

test('caddy：值里的换行同样被生成器拒绝（原有第二道关未回退）', () => {
  const { headers } = validatePolicy(basePolicy());
  headers['Referrer-Policy'].value = 'no-referrer\r\nrespond "x" 200';
  assert.throws(
    () => caddy.generate({ headers, remove: [] }, {}),
    /会被注入进 Caddyfile 的指令语法/
  );
});

test('htaccess：绕过策略层直接渲染时，非法 remove 被生成器拒绝', () => {
  const policy = unvalidatedPolicy([CADDY_INJECTION.replace(/respond "INJECTED-BY-POLICY" 200/g, 'Header always set X-Evil "1"')]);
  assert.throws(() => htaccess.generate(policy), /会被注入进 \.htaccess 的指令语法/);
});

test('htaccess：合法 remove 渲染为 Header always unset', () => {
  const out = htaccess.generate(unvalidatedPolicy(['X-Powered-By'])).content;
  assert.match(out, /Header always unset X-Powered-By/);
});

test('nginx：remove 不参与渲染（该渲染点没有注入面），注入载荷不会出现在产物里', () => {
  /* 这条用例是为了把"三个渲染点"逐个说清楚：nginx 生成器根本不输出删除指令
     （nginx 删头需要 more_clear_headers 模块，超出本工具的零依赖范围），
     所以这里既没有注入面、也没有"修好了"这回事 —— 只有"确认它确实不渲染"。 */
  const policy = unvalidatedPolicy([CADDY_INJECTION]);
  const out = nginx.generate(policy).content;
  assert.doesNotMatch(out, /INJECTED-BY-POLICY/);
  assert.doesNotMatch(out, /X-Powered-By/);
  assert.doesNotMatch(out, /INJECTED/);
});

test('nginx：产物只有 add_header 行，逐行都符合指令语法', () => {
  const policy = unvalidatedPolicy([CADDY_INJECTION]);
  const out = nginx.generate(policy).content;
  for (const line of out.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    assert.match(trimmed, /^add_header\s+[!#$%&'*+\-.^_`|~0-9A-Za-z]+\s+"[^"]*"\s+always;$/, `可疑产物行：${line}`);
  }
});

/* ------------------------------------------------------------------ *
 * 3. 全量 generate：非法 remove 下不落盘任何文件
 * ------------------------------------------------------------------ */

test('全量 generate 在非法 remove 下抛错，且不落盘任何文件（含部分产物）', () => {
  const outDir = tmpDir('all-gen');
  const policy = unvalidatedPolicy([CADDY_INJECTION]);

  /* 复刻 index.mjs 的写盘顺序：先由 generateAll 产出全部内容，再逐个写文件。
     任何生成器抛错都发生在写盘之前 —— 因此不允许出现"半套产物"。 */
  assert.throws(() => {
    const artifacts = generateAll(policy, {});
    for (const { artifact, target } of planOutputPaths(outDir, artifacts)) {
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, artifact.content, 'utf8');
    }
  });

  assert.deepEqual(readdirSync(outDir), [], '输出目录必须为空：不能留下半套产物');
});

test('全量 generate 在合法 remove 下正常产出六份配置', () => {
  const outDir = tmpDir('all-gen-ok');
  const policy = validatePolicy(basePolicy({ remove: ['X-Powered-By', 'Server'] }));
  const artifacts = generateAll(policy, {});
  for (const { artifact, target } of planOutputPaths(outDir, artifacts)) {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, artifact.content, 'utf8');
  }
  assert.equal(artifacts.length, 6);
  for (const a of artifacts) assert.ok(a.content.length > 0, `${a.id} 产物为空`);
});

test('策略层拒绝发生在生成之前：loadPolicy 语义下非法 remove 连产物规划都到不了', () => {
  /* 这条钉死"退出码 2"的来源：validatePolicy 抛 PolicyError → index.mjs 的
     catch 把它转成退出码 2，而不是渲染出一份带注入指令的配置。 */
  assert.throws(() => validatePolicy(basePolicy({ remove: [CADDY_INJECTION] })), PolicyError);
});
