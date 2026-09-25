/**
 * SARIF 输出测试（全部离线，不联网）
 *
 * 钉死三件在 Code Scanning 面板里会直接影响体验的事：
 *   1. 结构合规（SARIF 2.1.0 必填字段 + GitHub 的最低要求）
 *   2. 问题 → level 的映射，以及"什么不该上报"（extra 头、拉取失败）
 *   3. **指纹跨运行稳定** —— 这是最容易被写坏的一处：
 *      只要指纹里混进实际值/期望值/时间戳，同一个问题每跑一次 CI 就新开一条告警。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  entryFromSingle,
  collectProblems,
  ruleIdFor,
  fingerprintFor,
  toSarif,
  validateSarif,
  renderSarifSummary,
} from '../src/lib/sarif.mjs';

const POLICY_PATH = 'headers.policy.json';

/** 单 URL 的校验结果（形态与 verifyUrl 的 result.results 一致） */
const SINGLE_RESULTS = [
  {
    name: 'Strict-Transport-Security',
    status: 'pass',
    severity: 'medium',
    expected: 'max-age=31536000; includeSubDomains',
    actual: 'max-age=31536000; includeSubDomains',
    why: '强制 HTTPS',
    note: '一致',
  },
  {
    name: 'Referrer-Policy',
    status: 'missing',
    severity: 'low',
    expected: 'strict-origin-when-cross-origin',
    actual: null,
    why: '避免 URL 信息外泄',
    note: '线上未返回该响应头',
  },
  {
    name: 'X-Frame-Options',
    status: 'mismatch',
    severity: 'medium',
    expected: 'DENY',
    actual: 'SAMEORIGIN',
    why: '防点击劫持',
    note: '取值不同',
  },
  {
    name: 'Server',
    status: 'extra',
    severity: 'info',
    expected: null,
    actual: 'nginx/1.24.0',
    value: 'nginx/1.24.0',
    note: '策略未声明该头',
  },
];

const ENTRY = entryFromSingle({ url: 'https://example.com/', results: SINGLE_RESULTS, meta: { status: 200 } });

function build(entries = [ENTRY], overrides = {}) {
  return toSarif({
    entries,
    policyPath: POLICY_PATH,
    version: '0.1.0',
    startedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  });
}

/* ------------------------------------------------------------------ *
 * 1. 结构与必填字段
 * ------------------------------------------------------------------ */

test('SARIF 2.1.0 必填结构齐全且通过自检', () => {
  const sarif = build();
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.$schema.includes('sarif-2.1.0'));
  assert.equal(sarif.runs.length, 1);

  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'header-forge');
  assert.equal(run.tool.driver.version, '0.1.0');
  assert.ok(Array.isArray(run.tool.driver.rules));
  assert.ok(Array.isArray(run.results));

  const { ok, problems } = validateSarif(sarif);
  assert.deepEqual(problems, []);
  assert.equal(ok, true);
});

test('每条结果都有 ruleId / message / level / 位置 / 指纹，且 ruleId 在 rules 里声明', () => {
  const sarif = build();
  const run = sarif.runs[0];
  const ruleIds = new Set(run.tool.driver.rules.map((r) => r.id));

  assert.ok(run.results.length > 0);
  for (const result of run.results) {
    assert.ok(ruleIds.has(result.ruleId), `ruleId 未声明：${result.ruleId}`);
    assert.ok(result.message.text.length > 0);
    assert.ok(['error', 'warning', 'note', 'none'].includes(result.level));
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, POLICY_PATH);
    assert.ok(Object.keys(result.partialFingerprints).length > 0);
    assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId, 'ruleIndex 必须指回同一规则');
  }
});

test('JSON 可序列化并可解析回来（写完落盘再读也是同一份）', () => {
  const sarif = build();
  const text = JSON.stringify(sarif, null, 2);
  const parsed = JSON.parse(text);
  assert.deepEqual(parsed, sarif);
  assert.equal(validateSarif(parsed).ok, true);
});

test('自检能发现坏文档（不是永远返回 ok）', () => {
  assert.equal(validateSarif(null).ok, false);
  assert.equal(validateSarif({ version: '2.1.0', runs: [] }).ok, false);

  const broken = build();
  delete broken.runs[0].results[0].message;
  const { ok, problems } = validateSarif(broken);
  assert.equal(ok, false);
  assert.ok(problems.some((p) => p.includes('缺少 message.text')));

  const orphan = build();
  orphan.runs[0].results[0].ruleId = 'header-forge/missing/not-declared';
  assert.match(validateSarif(orphan).problems.join('\n'), /不在 rules 中声明/);

  const noFingerprint = build();
  delete noFingerprint.runs[0].results[0].partialFingerprints;
  assert.match(validateSarif(noFingerprint).problems.join('\n'), /缺少 partialFingerprints/);
});

/* ------------------------------------------------------------------ *
 * 2. 映射与"什么不该上报"
 * ------------------------------------------------------------------ */

test('只有 missing / mismatch 进入 SARIF；extra 与 pass 不上报', () => {
  const problems = collectProblems([ENTRY]);
  assert.deepEqual(
    problems.map((p) => `${p.status}:${p.header}`),
    ['missing:Referrer-Policy', 'mismatch:X-Frame-Options']
  );

  const sarif = build();
  assert.equal(sarif.runs[0].results.length, 2);
  assert.doesNotMatch(JSON.stringify(sarif.runs[0].results), /Server/);
  /* extra 头没有丢：留在 run.properties 里备查 */
  assert.deepEqual(sarif.runs[0].properties.extraHeaders, [
    { url: 'https://example.com/', header: 'Server', value: 'nginx/1.24.0' },
  ]);
});

test('level 由策略 severity 决定：medium → warning、low → note', () => {
  const sarif = build();
  const byRule = Object.fromEntries(sarif.runs[0].results.map((r) => [r.ruleId, r.level]));

  assert.equal(byRule['header-forge/missing/referrer-policy'], 'note'); // low
  assert.equal(byRule['header-forge/mismatch/x-frame-options'], 'warning'); // medium
});

test('severity 到 level 的全量映射（critical/high → error）', () => {
  const entry = entryFromSingle({
    url: 'https://example.com/',
    results: [
      { name: 'A-Header', status: 'missing', severity: 'critical', expected: 'x', actual: null },
      { name: 'B-Header', status: 'missing', severity: 'high', expected: 'x', actual: null },
      { name: 'C-Header', status: 'missing', severity: 'medium', expected: 'x', actual: null },
      { name: 'D-Header', status: 'missing', severity: 'low', expected: 'x', actual: null },
      { name: 'E-Header', status: 'missing', severity: 'info', expected: 'x', actual: null },
    ],
  });
  const sarif = build([entry]);
  const levels = sarif.runs[0].results.map((r) => r.level);
  assert.deepEqual(levels, ['error', 'error', 'warning', 'note', 'note']);
});

test('拉取失败的地址不进 results，但记录在 properties 且 executionSuccessful=false', () => {
  const errored = {
    url: 'https://dead.example/',
    status: 'error',
    error: 'ECONNREFUSED',
    summary: null,
    results: [],
  };
  const sarif = build([ENTRY, errored]);

  assert.equal(sarif.runs[0].results.length, 2, '只上报 CONTAINER 里的真实问题');
  assert.equal(sarif.runs[0].invocation.executionSuccessful, false);
  assert.deepEqual(sarif.runs[0].properties.unreachable, [
    { url: 'https://dead.example/', error: 'ECONNREFUSED' },
  ]);
});

test('ruleId 不含 URL（同一类问题在多个路径上归并到同一条规则）', () => {
  const a = entryFromSingle({ url: 'https://example.com/', results: SINGLE_RESULTS });
  const b = entryFromSingle({ url: 'https://example.com/admin', results: SINGLE_RESULTS });
  const sarif = build([a, b]);

  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.deepEqual(ruleIds, ['header-forge/mismatch/x-frame-options', 'header-forge/missing/referrer-policy']);
  for (const id of ruleIds) assert.doesNotMatch(id, /example\.com/);

  /* 规则只有 2 条，结果有 4 条（两个地址各两条问题） */
  assert.equal(sarif.runs[0].results.length, 4);
  assert.equal(ruleIdFor({ status: 'missing', header: 'Referrer-Policy' }), 'header-forge/missing/referrer-policy');
});

/* ------------------------------------------------------------------ *
 * 3. 指纹稳定性（Code Scanning 面板不刷屏的关键）
 * ------------------------------------------------------------------ */

test('同一问题跨两次运行的指纹完全一致', () => {
  const first = build();
  const second = build();

  const fp = (s) => s.runs[0].results.map((r) => r.partialFingerprints['headerForgeFingerprint/v1']);
  assert.deepEqual(fp(first), fp(second));
  assert.equal(JSON.stringify(first.runs[0].results), JSON.stringify(second.runs[0].results));
});

test('指纹不含实际值/期望值：站点改坏了取值，仍是同一条告警', () => {
  const before = { ...SINGLE_RESULTS[2], actual: 'SAMEORIGIN' };
  const after = { ...SINGLE_RESULTS[2], actual: 'ALLOWALL' };

  const fpBefore = fingerprintFor({ status: 'mismatch', url: 'https://example.com/', header: 'X-Frame-Options', actual: before.actual });
  const fpAfter = fingerprintFor({ status: 'mismatch', url: 'https://example.com/', header: 'X-Frame-Options', actual: after.actual });

  assert.equal(fpBefore, fpAfter);
  assert.equal(fpBefore, fingerprintFor({ status: 'mismatch', url: 'https://example.com/', header: 'X-Frame-Options' }));
});

test('指纹不含时间戳：文档头的 startTimeUtc 变了也不影响', () => {
  const a = build([ENTRY], { startedAt: '2026-01-01T00:00:00.000Z' });
  const b = build([ENTRY], { startedAt: '2026-06-06T12:34:56.000Z' });

  assert.notEqual(a.runs[0].invocation.startTimeUtc, b.runs[0].invocation.startTimeUtc);
  assert.deepEqual(
    a.runs[0].results.map((r) => r.partialFingerprints['headerForgeFingerprint/v1']),
    b.runs[0].results.map((r) => r.partialFingerprints['headerForgeFingerprint/v1'])
  );
});

test('不同 URL / 不同头 / 不同问题类型 → 指纹必然不同', () => {
  const base = { status: 'missing', url: 'https://example.com/', header: 'Referrer-Policy' };
  const set = new Set([
    fingerprintFor(base),
    fingerprintFor({ ...base, url: 'https://example.com/admin' }),
    fingerprintFor({ ...base, header: 'Content-Security-Policy' }),
    fingerprintFor({ ...base, status: 'mismatch' }),
  ]);
  assert.equal(set.size, 4);
});

test('头名大小写不影响指纹（同一问题必须归到同一条）', () => {
  assert.equal(
    fingerprintFor({ status: 'missing', url: 'https://example.com/', header: 'Referrer-Policy' }),
    fingerprintFor({ status: 'missing', url: 'https://example.com/', header: 'referrer-policy' })
  );
});

/* ------------------------------------------------------------------ *
 * 4. 摘要输出
 * ------------------------------------------------------------------ */

test('控制台摘要报出规则数、结果数、分级与"结果数与输入一致"', () => {
  const sarif = build();
  const text = renderSarifSummary({ path: 'out/results.sarif', sarif, expectedProblems: 2 });
  assert.match(text, /SARIF 已写入：out\/results\.sarif/);
  assert.match(text, /规则 2 条 · 结果 2 条/);
  assert.match(text, /输入问题数 2 —— 结果数与之一致/);
});
