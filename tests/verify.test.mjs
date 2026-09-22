/**
 * 一致性校验测试
 *
 * 比对的语义是这里最容易出错的地方：过严会天天误报，过松会漏掉真实降级。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateHeaders, compareHeader } from '../src/verify.mjs';

const policy = {
  headers: {
    'Strict-Transport-Security': {
      name: 'Strict-Transport-Security',
      value: 'max-age=31536000; includeSubDomains',
      severity: 'medium',
      why: '强制 HTTPS',
    },
    'Content-Security-Policy': {
      name: 'Content-Security-Policy',
      value: "default-src 'self'; frame-ancestors 'none'",
      severity: 'medium',
      why: '',
    },
    'X-Content-Type-Options': {
      name: 'X-Content-Type-Options',
      value: 'nosniff',
      severity: 'low',
      why: '',
    },
  },
};

const byName = (results) => Object.fromEntries(results.map((r) => [r.name, r]));

/* ---------------- compareHeader：单头语义 ---------------- */

test('HSTS：线上 max-age 更大算通过（提供更强保护）', () => {
  const r = compareHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains',
    'max-age=63072000; includeSubDomains; preload'
  );
  assert.equal(r.ok, true);
  assert.match(r.note, /允许更强/);
});

test('HSTS：线上 max-age 更小判为不符', () => {
  const r = compareHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains',
    'max-age=600; includeSubDomains'
  );
  assert.equal(r.ok, false);
  assert.match(r.note, /max-age 偏小/);
});

test('HSTS：线上缺少 includeSubDomains 判为不符', () => {
  const r = compareHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains',
    'max-age=31536000'
  );
  assert.equal(r.ok, false);
  assert.match(r.note, /includeSubDomains/);
});

test('HSTS：max-age=0 视为无效', () => {
  const r = compareHeader('Strict-Transport-Security', 'max-age=31536000', 'max-age=0');
  assert.equal(r.ok, false);
  assert.match(r.note, /缺少有效的 max-age/);
});

test('HSTS：allowStronger=false 时要求完全一致', () => {
  const r = compareHeader('Strict-Transport-Security', 'max-age=31536000', 'max-age=63072000', {
    allowStronger: false,
  });
  assert.equal(r.ok, false);
  assert.match(r.note, /与策略不等/);
});

test('CSP：线上缺少策略要求的指令判为不符', () => {
  const r = compareHeader(
    'Content-Security-Policy',
    "default-src 'self'; frame-ancestors 'none'",
    "default-src 'self'"
  );
  assert.equal(r.ok, false);
  assert.match(r.note, /缺少指令：frame-ancestors/);
});

test('CSP：线上有额外指令（更严格）算通过', () => {
  const r = compareHeader(
    'Content-Security-Policy',
    "default-src 'self'",
    "default-src 'self'; object-src 'none'; upgrade-insecure-requests"
  );
  assert.equal(r.ok, true);
  assert.match(r.note, /附加指令/);
});

test('CSP：指令取值被放宽判为不符', () => {
  const r = compareHeader(
    'Content-Security-Policy',
    "script-src 'self'",
    "script-src 'self' 'unsafe-inline'"
  );
  assert.equal(r.ok, false);
  assert.match(r.note, /指令取值与策略不一致/);
});

test('X-Frame-Options：忽略大小写', () => {
  assert.equal(compareHeader('X-Frame-Options', 'DENY', 'deny').ok, true);
  assert.equal(compareHeader('X-Frame-Options', 'DENY', 'SAMEORIGIN').ok, false);
});

test('普通头：忽略大小写与多余空白', () => {
  assert.equal(compareHeader('X-Content-Type-Options', 'nosniff', '  NoSniff  ').ok, true);
  assert.equal(compareHeader('X-Content-Type-Options', 'nosniff', 'sniff').ok, false);
});

/* ---------------- evaluateHeaders：整体归类 ---------------- */

test('缺失的头被归类为 missing 并带上策略理由', () => {
  const results = evaluateHeaders(policy, { 'x-content-type-options': 'nosniff' });
  const map = byName(results);
  assert.equal(map['Strict-Transport-Security'].status, 'missing');
  assert.equal(map['Strict-Transport-Security'].why, '强制 HTTPS');
  assert.equal(map['X-Content-Type-Options'].status, 'pass');
});

test('全部符合时无 missing / mismatch', () => {
  const results = evaluateHeaders(policy, {
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
  });
  assert.equal(results.filter((r) => r.status === 'missing' || r.status === 'mismatch').length, 0);
});

test('响应头值数组会被合并后比较（Set-Cookie 那类多值情形）', () => {
  const results = evaluateHeaders(
    { headers: { 'X-Test': { name: 'X-Test', value: 'a, b', severity: 'low', why: '' } } },
    { 'x-test': ['a', 'b'] }
  );
  assert.equal(results[0].status, 'pass');
});

test('策略外的安全相关头被标为 extra（提示人工确认）', () => {
  const results = evaluateHeaders(policy, {
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'x-powered-by': 'Express',
    server: 'nginx/1.18.0',
  });
  const map = byName(results);
  assert.equal(map['X-Powered-By'].status, 'extra');
  assert.equal(map['Server'].status, 'extra');
});

test('传递实际值时不会因为大小写差异误报', () => {
  const results = evaluateHeaders(
    { headers: { 'Referrer-Policy': { name: 'Referrer-Policy', value: 'no-referrer', severity: 'low', why: '' } } },
    { 'Referrer-Policy': 'No-Referrer' }
  );
  assert.equal(results[0].status, 'pass');
});
