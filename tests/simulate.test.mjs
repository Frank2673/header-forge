/**
 * 本地模拟器测试
 *
 * 这是整个项目最有价值的一组测试：它验证的是一条完整链路 ——
 *   策略 → 生成器 → 配置文件 → 应用到真实 HTTP 响应 → 校验器 → 一致性通过
 * 任何一个环节出错（值写漏、转义错误、格式不对）都会在这里暴露。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseGeneratedConfig, startSimulator } from '../src/simulate.mjs';
import { generateAll } from '../src/generators/index.mjs';
import { verifyUrl, evaluateHeaders } from '../src/verify.mjs';
import { validatePolicy } from '../src/lib/policy.mjs';

/** 一份合规策略（与真实站点同构，但用虚构域名避免任何外部依赖） */
const policy = validatePolicy({
  version: 1,
  headers: {
    'Strict-Transport-Security': {
      value: 'max-age=31536000; includeSubDomains',
      severity: 'medium',
      why: '强制 HTTPS',
    },
    'Content-Security-Policy': {
      value: "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
      severity: 'medium',
      why: '限制资源来源',
    },
    'X-Content-Type-Options': { value: 'nosniff', severity: 'low', why: '' },
    'Referrer-Policy': { value: 'strict-origin-when-cross-origin', severity: 'low', why: '' },
    'Permissions-Policy': { value: 'geolocation=(), camera=()', severity: 'info', why: '' },
    'X-Frame-Options': { value: 'DENY', severity: 'medium', why: '' },
    'Cross-Origin-Opener-Policy': { value: 'same-origin', severity: 'low', why: '' },
  },
});

/* ---------------- 配置解析 ---------------- */

test('从 _headers 产物解析响应头', () => {
  const artifact = generateAll(policy, { only: ['cloudflare-pages'] })[0];
  const headers = parseGeneratedConfig(artifact.content);
  assert.equal(headers['Strict-Transport-Security'], 'max-age=31536000; includeSubDomains');
  assert.equal(headers['X-Frame-Options'], 'DENY');
  assert.equal(Object.keys(headers).length, Object.keys(policy.headers).length);
});

test('从 vercel.json 产物解析响应头', () => {
  const artifact = generateAll(policy, { only: ['vercel'] })[0];
  const headers = parseGeneratedConfig(artifact.content);
  assert.equal(headers['Referrer-Policy'], 'strict-origin-when-cross-origin');
  assert.equal(headers['Content-Security-Policy'], policy.headers['Content-Security-Policy'].value);
});

/* ---------------- 端到端一致性 ---------------- */

test('模拟器用生成的 _headers 服务时，校验器判定完全符合策略', async () => {
  const artifact = generateAll(policy, { only: ['cloudflare-pages'] })[0];
  const sim = await startSimulator({ configText: artifact.content });

  try {
    const result = await verifyUrl(policy, sim.url);
    assert.equal(result.ok, true, `请求失败：${result.error}`);

    const problems = result.results.filter((r) => r.status === 'missing' || r.status === 'mismatch');
    assert.deepEqual(problems, [], `存在不符合项：${JSON.stringify(problems, null, 2)}`);

    const passed = result.results.filter((r) => r.status === 'pass');
    assert.equal(passed.length, Object.keys(policy.headers).length);
  } finally {
    await sim.close();
  }
});

test('模拟器用 vercel.json 产物服务时同样符合策略（跨格式一致性）', async () => {
  const artifact = generateAll(policy, { only: ['vercel'] })[0];
  const sim = await startSimulator({ configText: artifact.content });

  try {
    const result = await verifyUrl(policy, sim.url);
    const problems = result.results.filter((r) => r.status === 'missing' || r.status === 'mismatch');
    assert.deepEqual(problems, []);
  } finally {
    await sim.close();
  }
});

test('配置里少一个头时，模拟器会如实暴露不符（证明校验不是走过场）', () => {
  const artifact = generateAll(policy, { only: ['cloudflare-pages'] })[0];
  /* 人为删掉 Referrer-Policy 那一行，模拟生成器遗漏 */
  const tampered = artifact.content
    .split('\n')
    .filter((line) => !line.includes('Referrer-Policy'))
    .join('\n');

  const headers = parseGeneratedConfig(tampered);
  assert.equal(headers['Referrer-Policy'], undefined, '被删的头不应出现在解析结果中');

  const results = evaluateHeaders(policy, headers);
  const missing = results.filter((r) => r.status === 'missing');
  assert.equal(missing.length, 1);
  assert.equal(missing[0].name, 'Referrer-Policy');
});

test('模拟器默认返回一个可用于验证的 HTML 页面', async () => {
  const sim = await startSimulator({
    configText: '/*\n  X-Test: 1\n',
  });
  try {
    const res = await fetch(sim.url);
    const body = await res.text();
    assert.equal(res.status, 200);
    assert.match(body, /header-forge/);
    assert.equal(res.headers.get('x-test'), '1');
  } finally {
    await sim.close();
  }
});

test('模拟器可指定端口', async () => {
  const sim = await startSimulator({ configText: '/*\n  X-A: 1\n', port: 0 });
  try {
    assert.match(sim.url, /^http:\/\/127\.0\.0\.1:\d+\/$/);
  } finally {
    await sim.close();
  }
});
