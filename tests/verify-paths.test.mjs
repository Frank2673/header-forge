/**
 * `--paths` 批量校验的测试（全部离线：只连 127.0.0.1 上的进程内假站点）
 *
 * 这里钉死三件事：
 *   1. `--paths` 的解析形态（逗号 / 换行 / @文件 / 相对与绝对 URL）
 *   2. 汇总计数与**退出码语义**：0 全部一致 / 1 存在不一致 / 2 参数或运行错误
 *   3. 报告里"错误"与"不一致"必须分开 —— 拉不到响应时不能算成"不合规"
 */

import { test, after, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  collectPathEntries,
  resolveTargets,
  classifyVerifyResult,
  summarizeBatch,
  exitCodeForBatch,
  renderBatchMarkdown,
  renderBatchJson,
  renderBatchSummary,
  BATCH_STATUS,
} from '../src/lib/batch.mjs';
import { validatePolicy } from '../src/lib/policy.mjs';
import { verifyUrl } from '../src/verify.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_DIR = join(REPO, 'tmp', 'verify-paths-fixture', 'test-out');

const POLICY = validatePolicy({
  version: 1,
  headers: {
    'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains', severity: 'medium' },
    'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'", severity: 'medium' },
    'X-Content-Type-Options': { value: 'nosniff', severity: 'low' },
    'Referrer-Policy': { value: 'strict-origin-when-cross-origin', severity: 'low' },
    'X-Frame-Options': { value: 'DENY', severity: 'medium' },
  },
});

const FULL = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Frame-Options': 'DENY',
};

/** 进程内假站点：按路径返回不同响应头（只监听 127.0.0.1） */
let server;
let base;

before(async () => {
  server = http.createServer((req, res) => {
    const path = req.url.split('?')[0];
    const headers = { ...FULL };
    if (path === '/relaxed') delete headers['Referrer-Policy'];
    if (path === '/weakened') {
      headers['Referrer-Policy'] = 'unsafe-url';
      headers['X-Frame-Options'] = 'SAMEORIGIN';
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
    res.end('<h1>fixture</h1>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((r) => server.close(r));
  rmSync(join(REPO, 'tmp', 'verify-paths-fixture', 'test-out'), { recursive: true, force: true });
});

/** 跑一批 URL（串行，和 cmdVerifyMany 的顺序一致） */
async function runBatch(urls) {
  const entries = [];
  for (const url of urls) {
    const result = await verifyUrl(POLICY, url, { timeoutMs: 3000 });
    const classified = classifyVerifyResult(result);
    entries.push({
      url,
      raw: url,
      source: '--paths',
      status: classified.status,
      error: classified.error,
      summary: classified.summary,
      results: result.results || [],
      statusCode: result.meta ? result.meta.status : null,
      finalUrl: result.meta ? result.meta.finalUrl : null,
      ms: result.meta ? result.meta.ms : null,
    });
  }
  return entries;
}

/* ------------------------------------------------------------------ *
 * 1. --paths 解析
 * ------------------------------------------------------------------ */

test('--paths 支持逗号分隔，且可重复给出（累加、保持顺序）', () => {
  const entries = collectPathEntries(['/,/admin', '/api/v1']);
  assert.deepEqual(
    entries.map((e) => e.raw),
    ['/', '/admin', '/api/v1']
  );
});

test('--paths 支持换行分隔与多余空白', () => {
  const entries = collectPathEntries(['/a\n/b,\n\n  /c  ']);
  assert.deepEqual(
    entries.map((e) => e.raw),
    ['/a', '/b', '/c']
  );
});

test('--paths @文件：逐行读取，跳过空行与 # 注释', () => {
  mkdirSync(FIXTURE_DIR, { recursive: true });
  const listPath = join(FIXTURE_DIR, 'paths.txt');
  writeFileSync(listPath, '# 注释\n\n/\n/admin\n\n# 又一条注释\n/api\n', 'utf8');

  const entries = collectPathEntries([`@${listPath}`]);
  assert.deepEqual(
    entries.map((e) => e.raw),
    ['/', '/admin', '/api']
  );
  assert.equal(entries[0].source, listPath);
});

test('--paths @文件 不存在时报参数错误（不是静默忽略）', () => {
  assert.throws(() => collectPathEntries(['@tmp/definitely-missing-paths.txt']), /无法读取 --paths 的文件/);
});

test('--paths 只有分隔符 / 空值时抛错（不能悄悄变成"校验 0 个地址"）', () => {
  assert.throws(() => collectPathEntries([', ,\n']), /没有解析出任何地址/);
  assert.throws(() => collectPathEntries(['@']), /需要给出文件名/);
});

test('相对路径拼到基准地址；完整 URL 原样使用', () => {
  const targets = resolveTargets(
    collectPathEntries(['/, /admin', 'https://other.example/x']),
    'https://site.example/'
  );
  assert.deepEqual(
    targets.map((t) => t.url),
    ['https://site.example/', 'https://site.example/admin', 'https://other.example/x']
  );
});

test('没有基准地址时相对路径报参数错误；有完整 URL 则不需要基准', () => {
  assert.throws(() => resolveTargets(collectPathEntries(['/admin']), null), /没有基准地址/);
  const ok = resolveTargets(collectPathEntries(['https://a.example/x']), null);
  assert.equal(ok[0].url, 'https://a.example/x');
});

test('基准地址不合法时报参数错误', () => {
  assert.throws(() => resolveTargets(collectPathEntries(['/x']), 'not a url'), /不是合法地址/);
});

/* ------------------------------------------------------------------ *
 * 2. 逐条校验 + 汇总（离线假站点）
 * ------------------------------------------------------------------ */

test('全部一致：三个地址都返回合规头 → 汇总一致 3、退出码 0', async () => {
  const entries = await runBatch([`${base}/`, `${base}/x`, `${base}/teapot-ish`]);
  const summary = summarizeBatch(entries);

  assert.equal(summary.total, 3);
  assert.equal(summary.consistent, 3);
  assert.equal(summary.inconsistent, 0);
  assert.equal(summary.errors, 0);
  assert.equal(exitCodeForBatch(summary), 0);
  assert.ok(entries.every((e) => e.summary.passed === 5));
});

test('存在不一致：缺头的地址被逐条识别 → 退出码 1', async () => {
  const entries = await runBatch([`${base}/`, `${base}/relaxed`]);
  const summary = summarizeBatch(entries);

  assert.equal(summary.consistent, 1);
  assert.equal(summary.inconsistent, 1);
  assert.equal(summary.errors, 0);
  assert.equal(exitCodeForBatch(summary), 1);

  const relaxed = entries[1];
  assert.equal(relaxed.status, BATCH_STATUS.inconsistent);
  assert.equal(relaxed.summary.missing, 1);
  assert.equal(relaxed.results.filter((r) => r.status === 'missing')[0].name, 'Referrer-Policy');
});

test('取值被放宽也算不一致（头在 ≠ 合规）', async () => {
  const entries = await runBatch([`${base}/weakened`]);
  assert.equal(entries[0].status, BATCH_STATUS.inconsistent);
  assert.equal(entries[0].summary.mismatched, 2);
  assert.equal(exitCodeForBatch(summarizeBatch(entries)), 1);
});

test('拉取失败算运行错误（退出码 2），不能算成"不一致"', async () => {
  /* 127.0.0.1 上一个必然关闭的端口：连接被拒；全程不出本机 */
  const entries = await runBatch([`${base}/`, 'http://127.0.0.1:1/dead']);
  const summary = summarizeBatch(entries);

  assert.equal(summary.errors, 1);
  assert.equal(summary.consistent, 1);
  assert.equal(entries[1].status, BATCH_STATUS.error);
  assert.equal(entries[1].summary, null, '未取到响应时不应有合规计数');
  assert.equal(exitCodeForBatch(summary), 2, '运行错误优先于不一致');
});

test('既有不一致又有运行错误时，退出码报 2（错误优先，避免把"没测到"说成"不合规"）', async () => {
  const entries = await runBatch([`${base}/relaxed`, 'http://127.0.0.1:1/dead']);
  const summary = summarizeBatch(entries);
  assert.equal(summary.inconsistent, 1);
  assert.equal(summary.errors, 1);
  assert.equal(exitCodeForBatch(summary), 2);
});

test('classifyVerifyResult 对缺 ok 的结果按错误处理（不静默当作通过）', () => {
  assert.equal(classifyVerifyResult(null).status, BATCH_STATUS.error);
  assert.equal(classifyVerifyResult({ ok: false, error: 'TIMEOUT', results: [] }).error, 'TIMEOUT');
});

test('汇总计数之和等于输入条数（不吞地址、不重复计数）', async () => {
  const urls = [`${base}/`, `${base}/relaxed`, `${base}/weakened`, 'http://127.0.0.1:1/dead'];
  const entries = await runBatch(urls);
  const summary = summarizeBatch(entries);
  assert.equal(
    summary.consistent + summary.inconsistent + summary.errors,
    urls.length
  );
});

/* ------------------------------------------------------------------ *
 * 3. 报告渲染
 * ------------------------------------------------------------------ */

test('控制台摘要逐条列出地址并给出汇总', async () => {
  const entries = await runBatch([`${base}/`, `${base}/relaxed`, 'http://127.0.0.1:1/dead']);
  const text = renderBatchSummary({ entries, base });

  assert.match(text, /汇总：共 3 项 · ✅ 一致 1 · ❌ 不一致 1 · ⚠️ 错误 1/);
  assert.ok(text.includes(`${base}/relaxed`));
  assert.match(text, /\[缺失\] Referrer-Policy/);
  assert.match(text, /无法获取响应，未作判定/);
});

test('Markdown 报告：结论行随汇总变化，逐条结果齐全', async () => {
  const meta = { version: '0.1.0', startedAt: '2026-01-01T00:00:00.000Z', policyPath: 'fixtures/p.json' };

  const okEntries = await runBatch([`${base}/`]);
  const okMd = renderBatchMarkdown({ policy: POLICY, entries: okEntries, base, meta });
  assert.match(okMd, /结论：✅ 全部地址均符合策略/);

  const badEntries = await runBatch([`${base}/`, `${base}/relaxed`, 'http://127.0.0.1:1/dead']);
  const badMd = renderBatchMarkdown({ policy: POLICY, entries: badEntries, base, meta });
  assert.match(badMd, /结论：⚠️ 有 1 个地址无法校验（运行错误），本次不作合规判定/);
  assert.match(badMd, /\| ❌ 不一致 \| 1 \|/);
  assert.match(badMd, /\| ⚠️ 错误（未作判定） \| 1 \|/);
  for (const entry of badEntries) assert.ok(badMd.includes(entry.url));
});

test('JSON 报告：mode=batch、entries 数与输入一致、details 保留逐头明细', async () => {
  const entries = await runBatch([`${base}/`, `${base}/relaxed`]);
  const json = renderBatchJson({
    policy: POLICY,
    entries,
    base,
    meta: { version: '0.1.0', startedAt: '2026-01-01T00:00:00.000Z', policyPath: 'fixtures/p.json' },
  });

  assert.equal(json.mode, 'batch');
  assert.equal(json.tool, 'header-forge');
  assert.equal(json.entries.length, 2);
  assert.equal(json.summary.total, 2);
  assert.equal(json.compliant, false);
  assert.equal(json.entries[0].details.length, 5);
  /* JSON 必须可序列化 → 可解析（报告会被 CI 与下游工具读取） */
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(json)));
});
