/**
 * 真实世界语料测试
 *
 * 语料来自 9 个公开仓库的 `_headers`（来源见 fixtures/real-world/SOURCES.md）。
 * 这个测试的价值不是"多覆盖几行代码"，而是**在不是我造的样本上验证导入器**。
 *
 * 它已经抓到过一个真问题：真实配置里 `Cache-Control` 几乎总是按路径分别取值
 * （9 份里 4 份，最多 14 个路径块），这直接推翻了"全量导入"的默认行为 ——
 * 全量导入会把对方的按路径缓存规则压平成一条，重新发布就会搞坏线上缓存。
 * 见 src/importer.mjs 的 SECURITY_HEADERS。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importConfig, detectFormat, SECURITY_HEADERS } from '../src/importer.mjs';
import { generateAll, planOutputPaths } from '../src/generators/index.mjs';
import { validatePolicy } from '../src/lib/policy.mjs';

const CORPUS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'real-world');

function corpus() {
  return readdirSync(CORPUS_DIR)
    .filter((f) => f.endsWith('._headers'))
    .sort()
    .map((f) => ({ name: f, text: readFileSync(join(CORPUS_DIR, f), 'utf8') }));
}

test('语料存在且非空（语料被误删时测试要能发现）', () => {
  const files = corpus();
  assert.ok(files.length >= 8, `语料应至少有 8 份，实际 ${files.length}`);
  for (const f of files) {
    assert.ok(f.text.trim().length > 0, `${f.name} 为空`);
  }
});

test('每一份真实配置都能识别格式，且导入器不崩', () => {
  for (const f of corpus()) {
    assert.equal(detectFormat(f.text, '_headers'), 'headers', `${f.name} 应被识别为 headers 格式`);

    /* 不抛异常是底线 */
    const r = importConfig(f.text, { filename: '_headers' });
    assert.ok(typeof r.ok === 'boolean', `${f.name} 应返回结构化结果`);
  }
});

test('每一份真实配置要么导入成功，要么给出可操作的原因（不静默失败）', () => {
  for (const f of corpus()) {
    const r = importConfig(f.text, { filename: '_headers' });

    if (r.ok) {
      assert.ok(Object.keys(r.headers).length > 0, `${f.name} 成功但没有头`);
      continue;
    }

    /* 失败必须说清楚原因，且知道是"没有头"还是"只有非安全头" */
    assert.ok(r.error && r.error.length > 10, `${f.name} 的失败原因太短：${r.error}`);
    assert.ok(
      /没有.*任何响应头|都不是安全响应头|没有解析出任何路径块/.test(r.error),
      `${f.name} 的失败原因不可识别：${r.error}`
    );
  }
});

test('默认范围下导入的头全部属于安全类（这条不变式必须恒成立）', () => {
  for (const f of corpus()) {
    const r = importConfig(f.text, { filename: '_headers' });
    if (!r.ok) continue;

    for (const name of Object.keys(r.headers)) {
      assert.ok(SECURITY_HEADERS.has(name), `${f.name} 默认范围导入了非安全头：${name}`);
    }
  }
});

test('默认范围下不残留任何非安全头（它们只能出现在 ignored 里）', () => {
  for (const f of corpus()) {
    const r = importConfig(f.text, { filename: '_headers' });
    if (!r.ok) continue;

    for (const i of r.ignored) {
      assert.ok(!(i.name in r.headers), `${i.name} 同时出现在 headers 与 ignored`);
    }
  }
});

test('全量导入时，每一份真实配置都能得到至少一个头（语料本身都是有效配置）', () => {
  for (const f of corpus()) {
    const r = importConfig(f.text, { filename: '_headers', include: 'all' });
    assert.equal(r.ok, true, `${f.name} 全量导入应成功：${r.error}`);
    assert.ok(Object.keys(r.headers).length > 0, `${f.name} 全量导入后没有头`);
    assert.deepEqual(r.ignored, [], '全量导入时不该有 ignored');
  }
});

test('全量导入的头部集合是默认范围的超集（过滤只做减法，不引入新内容）', () => {
  for (const f of corpus()) {
    const def = importConfig(f.text, { filename: '_headers' });
    const all = importConfig(f.text, { filename: '_headers', include: 'all' });

    const defNames = def.ok ? Object.keys(def.headers) : [];
    for (const n of defNames) {
      assert.ok(n in all.headers, `${f.name} 的 ${n} 在全量导入里消失了`);
      assert.equal(all.headers[n], def.headers[n], `${f.name} 的 ${n} 取值应一致`);
    }
  }
});

test('真实语料里确实存在"按路径冲突"的头（否则这个语料没测到关键场景）', () => {
  /* 这条是元测试：如果语料里没有任何按路径冲突，那它就没有覆盖到
     "压平会改变线上行为"这个真实风险，语料该换。 */
  const withConflicts = corpus().filter((f) => {
    const r = importConfig(f.text, { filename: '_headers', include: 'all' });
    return r.ok && r.warnings.some((w) => w.includes('出现了多个取值'));
  });

  assert.ok(
    withConflicts.length >= 2,
    `语料里应有至少 2 份存在按路径冲突的配置，实际 ${withConflicts.length} 份 —— 语料可能失去代表性`
  );
});

test('真实语料覆盖了默认范围过滤（存在只有非安全头的文件）', () => {
  const nonSecurityOnly = corpus().filter((f) => {
    const r = importConfig(f.text, { filename: '_headers' });
    return !r.ok && r.ignored && r.ignored.length > 0;
  });

  assert.ok(
    nonSecurityOnly.length >= 1,
    `语料里应有至少 1 份"只有非安全头"的配置来验证过滤，实际 ${nonSecurityOnly.length} 份`
  );
});

test('真实语料里出现的头名都能被规范化（没有怪异字符漏进来）', () => {
  const seen = new Set();
  for (const f of corpus()) {
    const r = importConfig(f.text, { filename: '_headers', include: 'all' });
    for (const n of Object.keys(r.headers)) seen.add(n);
  }

  assert.ok(seen.size >= 10, `语料应覆盖至少 10 种头，实际 ${seen.size}`);
  for (const n of seen) {
    assert.match(n, /^[A-Z0-9][A-Za-z0-9-]*$/, `头名不规范：${n}`);
    assert.ok(!n.endsWith('-'), `头名不应以连字符结尾：${n}`);
  }
});

test('真实语料里出现的头，绝大多数已在 SECURITY_HEADERS 里有定论', () => {
  /* 真实世界用到的头，要么被接管、要么被明确排除 —— 不该有"没考虑过"的漏网 */
  const all = new Set();
  for (const f of corpus()) {
    const r = importConfig(f.text, { filename: '_headers', include: 'all' });
    for (const n of Object.keys(r.headers)) all.add(n);
  }

  /* 已知且刻意不接管的非安全头（清单是显式的，新增时要在这里补一行说明） */
  const knownNonSecurity = new Set([
    'Cache-Control',
    'Content-Type',
    'Access-Control-Allow-Origin',
    'Access-Control-Allow-Methods',
  ]);

  const unclassified = [...all].filter((n) => !SECURITY_HEADERS.has(n) && !knownNonSecurity.has(n));
  assert.deepEqual(
    unclassified,
    [],
    `发现未分类的头（需要决定接管还是排除）：${unclassified.join(', ')}`
  );
});

/* ------------------------- 产物落点（同名覆盖的回归） ------------------------- */

/** 一份满足基线的最小策略，供落点测试用 */
function baselinePolicy() {
  return validatePolicy({
    version: 1,
    headers: {
      'Strict-Transport-Security': { value: 'max-age=31536000; includeSubDomains' },
      'Content-Security-Policy': { value: "default-src 'self'; frame-ancestors 'none'" },
      'X-Content-Type-Options': { value: 'nosniff' },
      'Referrer-Policy': { value: 'strict-origin-when-cross-origin' },
    },
  });
}

test('**同名产物不会被静默覆盖** —— 落点由 planOutputPaths 显式决定', () => {
  /* 这条回归来自一次真实比对：站点线上 _headers 写着 Cloudflare 的注释，
     而新生成的是 Netlify 的 —— 因为两者同名，谁后写谁生效。内容恰好相同所以没出事。 */
  const planned = planOutputPaths('dist', generateAll(baselinePolicy()));

  const targets = planned.map((p) => p.target);
  assert.equal(new Set(targets).size, targets.length, `落点有重复：${targets.join(', ')}`);

  const headersArtifacts = planned.filter((p) => p.artifact.filename === '_headers');
  assert.equal(headersArtifacts.length, 2, '应有 cloudflare-pages 与 netlify 两份 _headers');
  assert.equal(headersArtifacts[0].target, 'dist/_headers', '第一份占住根下的名字');
  assert.equal(headersArtifacts[1].target, 'dist/netlify/_headers', '第二份进自己的子目录');
  assert.equal(headersArtifacts[1].disambiguated, true, '应标记为被消歧过');
  assert.equal(headersArtifacts[0].disambiguated, false);
});

test('无论生成器顺序如何，落点都不会被两个平台共用', () => {
  const forward = generateAll(baselinePolicy());
  const reversed = [...forward].reverse();

  for (const order of [forward, reversed]) {
    const targets = planOutputPaths('dist', order).map((p) => p.target);
    assert.equal(new Set(targets).size, targets.length, `落点有重复：${targets.join(', ')}`);
    assert.equal(targets.length, 6);
  }
});

test('按平台单独生成时，_headers 仍在根下的标准位置（站点部署依赖这一点）', () => {
  const planned = planOutputPaths('dist', generateAll(baselinePolicy(), { only: ['cloudflare-pages'] }));

  assert.equal(planned.length, 1);
  assert.equal(planned[0].target, 'dist/_headers');
  assert.equal(planned[0].disambiguated, false);
});

test('nginx / caddy 一直放自己的子目录（它们本来就不会与 _headers 撞名）', () => {
  const planned = planOutputPaths('dist', generateAll(baselinePolicy(), { only: ['nginx', 'caddy'] }));

  assert.equal(planned.find((p) => p.artifact.id === 'nginx').target, 'dist/nginx/nginx-security-headers.conf');
  assert.equal(planned.find((p) => p.artifact.id === 'caddy').target, 'dist/caddy/Caddyfile.headers');
  assert.equal(planned.every((p) => !p.disambiguated), true);
});
