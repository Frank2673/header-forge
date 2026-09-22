/**
 * 策略校验测试
 *
 * 策略会被渲染进 nginx / caddy 等配置语法，所以这里把「拒绝什么」钉死：
 * 结构错误、弱值、以及最危险的配置注入字符。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validatePolicy,
  canonicalHeaderName,
  parseHsts,
  parseDirectives,
  summarizePolicy,
  PolicyError,
} from '../src/lib/policy.mjs';

/** 一份最小合规策略，供各用例派生 */
function basePolicy(overrides = {}) {
  return {
    version: 1,
    headers: {
      'Strict-Transport-Security': {
        value: 'max-age=31536000; includeSubDomains',
        severity: 'medium',
      },
      'Content-Security-Policy': {
        value: "default-src 'self'; frame-ancestors 'none'",
        severity: 'medium',
      },
      'X-Content-Type-Options': { value: 'nosniff', severity: 'low' },
      'Referrer-Policy': { value: 'strict-origin-when-cross-origin', severity: 'low' },
      ...overrides,
    },
  };
}

test('合规策略可以通过校验', () => {
  const policy = validatePolicy(basePolicy());
  assert.equal(Object.keys(policy.headers).length, 4);
  assert.ok(policy.headers['Strict-Transport-Security']);
});

test('头部名会被归一化为标准写法', () => {
  const policy = validatePolicy(
    basePolicy({ 'x-content-type-options': { value: 'nosniff', severity: 'low' } })
  );
  assert.ok(policy.headers['X-Content-Type-Options']);
});

test('canonicalHeaderName 处理各类大小写', () => {
  assert.equal(canonicalHeaderName('content-security-policy'), 'Content-Security-Policy');
  assert.equal(canonicalHeaderName('X-FRAME-OPTIONS'), 'X-Frame-Options');
  assert.equal(canonicalHeaderName('referrer-policy'), 'Referrer-Policy');
});

test('拒绝非法头部名', () => {
  assert.throws(
    () => validatePolicy(basePolicy({ 'bad header': { value: 'x' } })),
    PolicyError
  );
});

test('拒绝空 headers', () => {
  assert.throws(() => validatePolicy({ headers: {} }), /不能为空/);
});

test('缺少安全基线要求的头会被拒绝', () => {
  const policy = basePolicy();
  delete policy.headers['Referrer-Policy'];
  assert.throws(() => validatePolicy(policy), /缺少安全基线要求的响应头：Referrer-Policy/);
});

test('HSTS max-age 过短会被拒绝', () => {
  assert.throws(
    () =>
      validatePolicy(
        basePolicy({ 'Strict-Transport-Security': { value: 'max-age=600; includeSubDomains' } })
      ),
    /max-age 过短/
  );
});

test('HSTS 缺少 includeSubDomains 会被拒绝', () => {
  assert.throws(
    () =>
      validatePolicy(
        basePolicy({ 'Strict-Transport-Security': { value: 'max-age=31536000' } })
      ),
    /includeSubDomains/
  );
});

test('配置注入防护：值里含换行直接拒绝', () => {
  assert.throws(
    () =>
      validatePolicy(
        basePolicy({
          'X-Content-Type-Options': { value: 'nosniff\r\nadd_header X-Evil "1"' },
        })
      ),
    /会被注入进生成的配置语法/
  );
});

test('配置注入防护：制表符与 NUL 同样拒绝', () => {
  assert.throws(() => validatePolicy(basePolicy({ 'Referrer-Policy': { value: 'no-referrer\tx' } })), PolicyError);
  assert.throws(() => validatePolicy(basePolicy({ 'Referrer-Policy': { value: 'no-referrer\0' } })), PolicyError);
});

test("CSP 的 script-src 含 'unsafe-inline' 被拒绝", () => {
  assert.throws(
    () =>
      validatePolicy(
        basePolicy({
          'Content-Security-Policy': {
            value: "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
          },
        })
      ),
    /unsafe-inline/
  );
});

test("CSP 的 style-src 含 'unsafe-inline' 是允许的（样式注入风险低于脚本）", () => {
  const policy = validatePolicy(
    basePolicy({
      'Content-Security-Policy': {
        value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
      },
    })
  );
  assert.ok(policy.headers['Content-Security-Policy']);
});

test('CSP 缺少 default-src 与 script-src 被拒绝', () => {
  assert.throws(
    () =>
      validatePolicy(
        basePolicy({ 'Content-Security-Policy': { value: "frame-ancestors 'none'" } })
      ),
    /default-src 或 script-src/
  );
});

test('既无 frame-ancestors 又无 X-Frame-Options 被拒绝', () => {
  assert.throws(
    () =>
      validatePolicy(
        basePolicy({ 'Content-Security-Policy': { value: "default-src 'self'" } })
      ),
    /点击劫持防护缺失/
  );
});

test('X-Frame-Options 取值受限', () => {
  assert.throws(
    () => validatePolicy(basePolicy({ 'X-Frame-Options': { value: 'ALLOWALL' } })),
    /DENY 或 SAMEORIGIN/
  );
  const ok = validatePolicy(basePolicy({ 'X-Frame-Options': { value: 'sameorigin' } }));
  assert.ok(ok.headers['X-Frame-Options']);
});

test('X-Content-Type-Options 只能是 nosniff', () => {
  assert.throws(
    () => validatePolicy(basePolicy({ 'X-Content-Type-Options': { value: 'sniff' } })),
    /只能是 nosniff/
  );
});

test('severity 取值受限', () => {
  assert.throws(
    () =>
      validatePolicy(
        basePolicy({ 'Referrer-Policy': { value: 'no-referrer', severity: 'urgent' } })
      ),
    /severity 非法/
  );
});

test('parseHsts 解析各字段', () => {
  assert.deepEqual(parseHsts('max-age=31536000; includeSubDomains; preload'), {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  });
  assert.deepEqual(parseHsts('max-age=0'), { maxAge: 0, includeSubDomains: false, preload: false });
  assert.deepEqual(parseHsts('garbage'), { maxAge: 0, includeSubDomains: false, preload: false });
});

test('parseDirectives 解析指令表', () => {
  const d = parseDirectives("default-src 'self'; script-src 'self' https://cdn.example.com; frame-ancestors 'none'");
  assert.equal(d['default-src'], "'self'");
  assert.equal(d['script-src'], "'self' https://cdn.example.com");
  assert.equal(d['frame-ancestors'], "'none'");
});

test('summarizePolicy 统计各严重度数量', () => {
  const policy = validatePolicy(basePolicy());
  const s = summarizePolicy(policy);
  assert.equal(s.headerCount, 4);
  assert.equal(s.bySeverity.medium, 2);
  assert.equal(s.bySeverity.low, 2);
});
