/**
 * 单元测试：往返一致性守卫
 *
 * 两件事：
 *   1. 真实策略的往返必须通过（这是反向导入的验收标准）
 *   2. **守卫本身必须能失败** —— 一个永远通过的守卫等于没有守卫，
 *      所以这里对比较逻辑做双向验证（能发现问题、不误报相同的内容）
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHeaderMaps, checkRoundTrip } from '../scripts/check-roundtrip.mjs';
import { loadPolicy, validatePolicy } from '../src/lib/policy.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/* ------------------------- 真实策略的往返 ------------------------- */

test('仓库真实策略：五种产物往返全部一致', () => {
  const policy = loadPolicy(resolve(ROOT, 'headers.policy.json'));
  const { results, failures, expectedCount } = checkRoundTrip(policy);

  assert.ok(expectedCount >= 4, '策略应至少包含基线那几个头');
  assert.equal(results.length, 5, '五个平台产物都要检查');
  assert.deepEqual(
    results.filter((r) => !r.ok),
    [],
    `有产物往返不一致：${results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.reason}`).join('; ')}`
  );
  assert.equal(failures, 0);
});

test('含双引号与反斜杠的值也能往返（转义不对称的高发区）', () => {
  const policy = validatePolicy({
    version: 1,
    headers: {
      'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains' },
      'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'" },
      'X-Content-Type-Options': { value: 'nosniff' },
      'Referrer-Policy': { value: 'strict-origin-when-cross-origin' },
      /* nginx / caddy 会把它转义成 \" —— 还原错了这条测试就会红 */
      Link: { value: '<https://cdn.example.com>; rel="preload"; as="script"' },
      /* 反斜杠同样要被正确还原 */
      'X-Test-Backslash': { value: 'a\\b"c' },
    },
  });

  const { results, failures } = checkRoundTrip(policy);
  assert.equal(failures, 0, `往返失败：${results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.reason}`).join('; ')}`);
});

test('Caddy 的删除指令不影响头部往返', () => {
  const policy = validatePolicy({
    version: 1,
    headers: {
      'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains' },
      'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'" },
      'X-Content-Type-Options': { value: 'nosniff' },
      'Referrer-Policy': { value: 'strict-origin-when-cross-origin' },
    },
    remove: ['X-Powered-By', 'Server'],
  });

  const { failures } = checkRoundTrip(policy);
  assert.equal(failures, 0);
});

/* ------------------------- 守卫的负向验证 ------------------------- */

test('diffHeaderMaps：完全相同时三项都为空（不误报）', () => {
  const { missing, extra, different } = diffHeaderMaps(
    { A: '1', B: '2' },
    { A: '1', B: '2' }
  );
  assert.deepEqual(missing, []);
  assert.deepEqual(extra, []);
  assert.deepEqual(different, []);
});

test('diffHeaderMaps：取值被改动会被抓出（含两边的值，便于定位）', () => {
  const { different } = diffHeaderMaps({ A: '1' }, { A: '1 ' });   // 只差一个空格

  assert.equal(different.length, 1);
  assert.equal(different[0].name, 'A');
  assert.equal(different[0].expected, '1');
  assert.equal(different[0].got, '1 ');
});

test('diffHeaderMaps：缺少与多出的头分别被抓出', () => {
  const { missing, extra } = diffHeaderMaps({ A: '1', B: '2' }, { A: '1', C: '3' });

  assert.deepEqual(missing, ['B']);
  assert.deepEqual(extra, ['C']);
});

test('diffHeaderMaps：大小写差异算不一致（往返必须逐字节相等）', () => {
  const { different } = diffHeaderMaps({ A: 'nosniff' }, { A: 'NOSNIFF' });
  assert.equal(different.length, 1);
});

test('diffHeaderMaps：空表两边都空时不报差异', () => {
  assert.deepEqual(diffHeaderMaps({}, {}), { missing: [], extra: [], different: [] });
});

test('守卫能抓出真实的不对称：用错格式解析必然失败', () => {
  /* 模拟"导入格式认错"这种真实故障：把 nginx 产物当 _headers 解析，
     得到的名字集合与取值都会错位 —— 比较逻辑必须判为不一致 */
  const wrong = diffHeaderMaps(
    { 'X-Frame-Options': 'DENY' },
    { 'Add_header X-Frame-Options "DENY" always;': 'x' }
  );

  assert.equal(wrong.missing.length, 1, '格式认错时必须报缺少');
  assert.equal(wrong.extra.length, 1, '格式认错时必须报多出');
  assert.deepEqual(wrong.different, []);

  /* 反向确认：同一份内容用正确格式解析后没有差异 */
  const right = diffHeaderMaps({ 'X-Frame-Options': 'DENY' }, { 'X-Frame-Options': 'DENY' });
  assert.deepEqual(right, { missing: [], extra: [], different: [] });
});
