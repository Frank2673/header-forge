/**
 * CSP 顾问测试
 *
 * 其中「按标签类型提取来源」是修复真实 bug 后补的回归测试：
 * 早期实现用宽松正则抓 href，把 <a href="https://github.com"> 当成了样式表来源，
 * 导致生成的 style-src 白名单被无谓放大 —— CSP 白名单过宽等于削弱防护。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cspHash,
  extractInlineScripts,
  extractInlineStyles,
  analyzePage,
  suggestCsp,
  checkHashDrift,
} from '../src/advise.mjs';

/* ---------------- hash 计算 ---------------- */

test('cspHash 符合 CSP 规范的格式', () => {
  const hash = cspHash('console.log(1)');
  assert.match(hash, /^sha256-[A-Za-z0-9+/]{43}=$/);
  const expected = createHash('sha256').update('console.log(1)', 'utf8').digest('base64');
  assert.equal(hash, `sha256-${expected}`);
});

test('cspHash 对内容敏感：内容变则 hash 变', () => {
  assert.notEqual(cspHash('a'), cspHash('b'));
  assert.equal(cspHash('same'), cspHash('same'));
});

/* ---------------- 内联块提取 ---------------- */

test('提取内联脚本：排除外链脚本', () => {
  const html = '<script src="/main.js"></script><script>var a=1;</script>';
  const blocks = extractInlineScripts(html);
  assert.equal(blocks.length, 1);
  assert.match(blocks[0].content, /var a=1/);
});

test('提取内联脚本：排除 JSON-LD 等数据块（CSP 不拦截它们）', () => {
  const html = [
    '<script type="application/ld+json">{"@type":"Person"}</script>',
    '<script type="application/json">{"a":1}</script>',
    '<script type="importmap">{"imports":{}}</script>',
    '<script>real();</script>',
  ].join('');
  const blocks = extractInlineScripts(html);
  assert.equal(blocks.length, 1, '只应留下真正可执行的脚本');
  assert.match(blocks[0].content, /real\(\)/);
});

test('提取内联样式块', () => {
  const html = '<style>body{color:red}</style><link rel="stylesheet" href="/a.css">';
  const blocks = extractInlineStyles(html);
  assert.equal(blocks.length, 1);
  assert.match(blocks[0].content, /color:red/);
});

/* ---------------- 来源提取（按标签类型） ---------------- */

test('锚点链接不得被当成样式来源（回归测试）', () => {
  const html = '<a href="https://github.com/Frank2673">GitHub</a>';
  const analysis = analyzePage(html);
  assert.deepEqual(analysis.origins['style-src'], [], 'a[href] 不是样式表');
  assert.deepEqual(analysis.origins['script-src'], []);
});

test('外链样式表进入 style-src', () => {
  const html = '<link rel="stylesheet" href="https://cdn.example.com/app.css">';
  assert.deepEqual(analyzePage(html).origins['style-src'], ['https://cdn.example.com']);
});

test('同源相对路径不产生来源条目（无需写进白名单）', () => {
  const html = '<link rel="stylesheet" href="/assets/css/style.css"><script src="/assets/js/main.js"></script>';
  const analysis = analyzePage(html);
  assert.deepEqual(analysis.origins['style-src'], []);
  assert.deepEqual(analysis.origins['script-src'], []);
});

test('图片与外链脚本分别进入正确的指令', () => {
  const html =
    '<img src="https://img.example.com/a.png"><script src="https://js.example.com/lib.js"></script>';
  const analysis = analyzePage(html);
  assert.deepEqual(analysis.origins['img-src'], ['https://img.example.com']);
  assert.deepEqual(analysis.origins['script-src'], ['https://js.example.com']);
});

test('内联脚本里的 fetch / WebSocket 进入 connect-src', () => {
  const html = `<script>
    fetch('https://api.example.com/data');
    new WebSocket('wss://socket.example.com/live');
  </script>`;
  const analysis = analyzePage(html);
  assert.deepEqual(analysis.origins['connect-src'].sort(), [
    'https://api.example.com',
    'wss://socket.example.com',
  ]);
});

test('内联事件属性会被统计（hash 对它们无效）', () => {
  const analysis = analyzePage('<button onclick="go()">x</button>');
  assert.equal(analysis.eventHandlers, 1);
});

/* ---------------- CSP 建议 ---------------- */

test('无内联脚本时给出不含 unsafe-inline 的强 CSP', () => {
  const analysis = analyzePage('<link rel="stylesheet" href="/a.css">');
  const { value, warnings } = suggestCsp(analysis);
  assert.ok(value.includes("script-src 'self'"));
  assert.ok(!value.includes('unsafe-inline'));
  assert.equal(warnings.length, 0);
});

test('有内联脚本时用 hash 放行，而不是 unsafe-inline', () => {
  const html = '<script>var theme=1;</script>';
  const analysis = analyzePage(html);
  const { value, hashes } = suggestCsp(analysis);
  assert.equal(hashes.length, 1);
  assert.ok(value.includes(`'${hashes[0]}'`), 'CSP 中应包含该 hash');
  assert.ok(!value.includes("'unsafe-inline'"), '不应退化为 unsafe-inline');
});

test('有内联事件属性时必须放行 unsafe-inline，并给出警告', () => {
  const analysis = analyzePage('<button onclick="go()">x</button>');
  const { value, warnings } = suggestCsp(analysis);
  assert.ok(value.includes("'unsafe-inline'"));
  assert.ok(warnings.some((w) => /内联事件属性/.test(w)));
});

test('style 属性会触发 style-src 放行 unsafe-inline（但不影响 script-src）', () => {
  const analysis = analyzePage('<div style="color:red">x</div>');
  const { value } = suggestCsp(analysis);
  const styleSrc = value.match(/style-src ([^;]+)/)[1];
  const scriptSrc = value.match(/script-src ([^;]+)/)[1];
  assert.ok(styleSrc.includes("'unsafe-inline'"));
  assert.ok(!scriptSrc.includes("'unsafe-inline'"));
});

test('生成结果包含全部加固指令', () => {
  const { value } = suggestCsp(analyzePage('<html></html>'));
  for (const directive of ['frame-ancestors', 'base-uri', 'form-action', 'object-src', 'upgrade-insecure-requests']) {
    assert.ok(value.includes(directive), `缺少 ${directive}`);
  }
});

/* ---------------- hash 漂移检查 ---------------- */

test('hash 漂移：策略与页面一致时通过', () => {
  const analysis = analyzePage('<script>var a=1;</script>');
  const policy = {
    headers: {
      'Content-Security-Policy': {
        value: `default-src 'self'; script-src 'self' '${analysis.inlineScripts[0].hash}'`,
      },
    },
  };
  const drift = checkHashDrift(policy, analysis);
  assert.equal(drift.consistent, true);
});

test('hash 漂移：页面改了脚本而策略未更新时被检出', () => {
  const oldAnalysis = analyzePage('<script>var a=1;</script>');
  const newAnalysis = analyzePage('<script>var a=2;</script>');
  const policy = {
    headers: {
      'Content-Security-Policy': {
        value: `default-src 'self'; script-src 'self' '${oldAnalysis.inlineScripts[0].hash}'`,
      },
    },
  };
  const drift = checkHashDrift(policy, newAnalysis);
  assert.equal(drift.consistent, false);
  assert.equal(drift.missingInPolicy.length, 1, '新脚本的 hash 未在策略中');
  assert.equal(drift.staleInPolicy.length, 1, '策略中的旧 hash 已过期');
});

test('hash 漂移：策略没有 CSP 时明确说明原因', () => {
  const drift = checkHashDrift({ headers: {} }, analyzePage('<html></html>'));
  assert.equal(drift.consistent, false);
  assert.match(drift.reason, /没有 CSP/);
});
