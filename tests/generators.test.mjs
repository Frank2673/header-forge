/**
 * 生成器测试
 *
 * 重点：
 *   1. `_headers` 的渲染与解析必须能往返（模拟器依赖解析器）
 *   2. nginx / caddy 的值必须正确转义（配置注入防护的第二道关）
 *   3. 相同策略必须产出相同结果（可复现，CI 会比对）
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateAll, GENERATOR_IDS } from '../src/generators/index.mjs';
import {
  renderHeadersFile,
  parseHeadersFile,
  resolveHeadersForPath,
  matchesPattern,
} from '../src/generators/headers-file.mjs';
import * as nginx from '../src/generators/nginx.mjs';
import * as caddy from '../src/generators/caddy.mjs';
import * as vercel from '../src/generators/vercel.mjs';

const policy = {
  headers: {
    'Strict-Transport-Security': {
      name: 'Strict-Transport-Security',
      value: 'max-age=31536000; includeSubDomains',
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
  remove: ['X-Powered-By'],
};

test('_headers 渲染格式：路径行 + 缩进头部', () => {
  const text = renderHeadersFile(policy, { pathPattern: '/*' });
  const lines = text.split('\n');
  assert.equal(lines.find((l) => l === '/*'), '/*');
  assert.ok(lines.some((l) => l === '  Strict-Transport-Security: max-age=31536000; includeSubDomains'));
  assert.ok(lines.some((l) => l === '  X-Content-Type-Options: nosniff'));
});

test('_headers 渲染 → 解析可往返', () => {
  const text = renderHeadersFile(policy, { pathPattern: '/*' });
  const blocks = parseHeadersFile(text);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].pattern, '/*');
  assert.equal(blocks[0].headers['Strict-Transport-Security'], 'max-age=31536000; includeSubDomains');
  assert.equal(blocks[0].headers['X-Content-Type-Options'], 'nosniff');
});

test('解析器忽略注释与空行，并对缺冒号的行容错', () => {
  const text = [
    '# 注释',
    '',
    '/*',
    '  X-Test: 1',
    '  这行没有冒号，应被忽略',
    '',
    '/assets/*',
    '  Cache-Control: max-age=60',
  ].join('\n');
  const blocks = parseHeadersFile(text);
  assert.equal(blocks.length, 2);
  assert.deepEqual(blocks[0].headers, { 'X-Test': '1' });
  assert.deepEqual(blocks[1].headers, { 'Cache-Control': 'max-age=60' });
});

test('路径匹配：/* 覆盖全部，前缀匹配生效', () => {
  assert.equal(matchesPattern('/*', '/anything'), true);
  assert.equal(matchesPattern('/assets/*', '/assets/app.css'), true);
  assert.equal(matchesPattern('/assets/*', '/other/app.css'), false);
  assert.equal(matchesPattern('/exact', '/exact'), true);
});

test('多块配置按路径合并（后匹配覆盖先匹配）', () => {
  const text = ['/*', '  X-A: 1', '  X-B: 2', '/assets/*', '  X-B: 3'].join('\n');
  const resolved = resolveHeadersForPath(text, '/assets/app.css');
  assert.equal(resolved['X-A'], '1');
  assert.equal(resolved['X-B'], '3');
});

test('nginx 生成器正确转义引号与反斜杠（防配置注入）', () => {
  assert.equal(nginx.escapeNginxValue('a"b'), 'a\\"b');
  assert.equal(nginx.escapeNginxValue('a\\b'), 'a\\\\b');
  assert.equal(nginx.escapeNginxValue('C:\\path"x'), 'C:\\\\path\\"x');

  const artifact = nginx.generate(policy);
  assert.ok(artifact.content.includes('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'));
  assert.ok(artifact.content.includes('always'));
});

test('caddy 生成器包含删除头部的语法', () => {
  const artifact = caddy.generate(policy);
  assert.ok(artifact.content.includes('-X-Powered-By'));
  assert.ok(artifact.content.includes('header {'));
});

test('vercel 生成器产出合法 JSON 且结构正确', () => {
  const artifact = vercel.generate(policy);
  const config = JSON.parse(artifact.content);
  assert.equal(config.headers.length, 1);
  assert.equal(config.headers[0].source, '/(.*)');
  const keys = config.headers[0].headers.map((h) => h.key);
  assert.deepEqual(keys.sort(), ['Strict-Transport-Security', 'X-Content-Type-Options']);
});

test('generateAll 默认产出全部五个平台', () => {
  const artifacts = generateAll(policy);
  assert.equal(artifacts.length, GENERATOR_IDS.length);
  assert.deepEqual(
    artifacts.map((a) => a.id).sort(),
    ['caddy', 'cloudflare-pages', 'netlify', 'nginx', 'vercel']
  );
});

test('generateAll 支持只生成指定平台', () => {
  const artifacts = generateAll(policy, { only: ['nginx', 'caddy'] });
  assert.deepEqual(artifacts.map((a) => a.id), ['nginx', 'caddy']);
});

test('generateAll 对未知平台报错', () => {
  assert.throws(() => generateAll(policy, { only: ['apache'] }), /未知的生成器：apache/);
});

test('相同策略重复生成结果完全一致（可复现）', () => {
  const a = generateAll(policy);
  const b = generateAll(policy);
  for (let i = 0; i < a.length; i++) {
    assert.equal(a[i].content, b[i].content, `${a[i].id} 的产物不确定`);
  }
});

test('每个生成器都带说明（部署要点不能缺失）', () => {
  for (const artifact of generateAll(policy)) {
    assert.ok(Array.isArray(artifact.notes), `${artifact.id} 缺少 notes`);
    assert.ok(artifact.notes.length > 0, `${artifact.id} 的 notes 为空`);
  }
});
