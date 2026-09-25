/**
 * Cloudflare 下发工具测试
 *
 * 三条刻意的设计决定：
 *
 * 1. **假 API 服务在测试文件内自建**（而不是复用 tmp/cloudflare-dryrun/fake-cf.mjs）。
 *    原因：`tmp/` 在 header-forge 的 .gitignore 里，测试若依赖它，别人 clone 下来就跑不了。
 *    tmp/ 那份是用来做「真 CLI + 独立进程」的端到端自证，两份互为独立实现 ——
 *    两边都对同一件事下断言，比一份源码被两处引用更能发现「实现与预期一起错」。
 *
 * 2. **不 spawn 子进程**：本机沙箱下 Node 的默认 `stdio: 'pipe'` 会 EPERM，
 *    所以这里直接 `import { runDeploy }` 在进程内调用（runDeploy 本来就是为可测性导出的）。
 *
 * 3. **令牌明文一次都不落盘**：这条不是靠人看，是靠断言 ——
 *    每个写文件的地方都扫一遍，输出文本也扫一遍。
 */

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadPolicy } from '../src/lib/policy.mjs';
import {
  EXIT_OK,
  EXIT_REMOTE_REJECT,
  EXIT_LOCAL_ERROR,
  MANAGED_PREFIX,
  PHASE,
  DEFAULT_BASE_URL,
  buildRulesetRules,
  planMerge,
  diagnoseApiFailure,
  flattenErrors,
  collectApiErrors,
  inspectToken,
  redactSecret,
  fingerprintSecret,
  describeSecret,
  scrubSecrets,
  snapshotFileName,
  buildDeployPlan,
  runDeploy,
} from '../src/deploy/cloudflare.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_ROOT = join(REPO, 'tmp', 'cloudflare-dryrun', 'test-out');
const POLICY_PATH = join(REPO, 'headers.policy.json');

/** 真实策略文件（不是手搓的 fixture：下发工具必须能吃下项目自己的策略） */
const policy = loadPolicy(POLICY_PATH);

/* 合成令牌：长得像 2026 新格式，但它是本测试编的，不是任何真实凭据 */
const TOKEN = 'cfut_' + 'A1b2C3d4E5f6G7h8I9j0'.repeat(2);
const LEGACY_TOKEN = 'A1b2C3d4E5'.repeat(4); // 恰好 40 位（旧格式）

/* ------------------------------------------------------------------ *
 * 进程内假 Cloudflare API
 * ------------------------------------------------------------------ */

const FAULT_PAYLOADS = {
  401: { status: 401, body: { success: false, errors: [{ code: 10000, message: 'Authentication error' }], messages: [], result: null } },
  403: {
    status: 403,
    body: { success: false, errors: [{ code: 9109, message: 'Unauthorized to access requested resource' }], messages: [], result: null },
  },
  9106: { status: 400, body: { success: false, errors: [{ code: 9106, message: 'Missing X-Auth-Email header' }], messages: [], result: null } },
  /* 逐字来自 tmp/commit-msg4.txt 记录的 CI 原始响应 */
  6111: {
    status: 400,
    body: { code: 6003, message: 'Invalid request headers', error_chain: [{ code: 6111, message: 'Invalid format for Authorization header' }] },
  },
};

/**
 * 请求侧只记录脱敏形态 —— 与 tmp/cloudflare-dryrun/fake-cf.mjs 同口径：
 * Authorization 头的明文用完即弃，日志里只留 前 2 位 + *** 与 sha256 前 12 位。
 * （这样「令牌不落盘」才能被断言，而不是靠人看。）
 */
function describeAuthHeader(headerValue) {
  if (!headerValue) return { scheme: null, redacted: null, sha256_12: null, length: 0 };
  const m = /^(\S+)\s+(.*)$/.exec(String(headerValue));
  const scheme = m ? m[1] : null;
  const value = m ? m[2] : String(headerValue);
  return {
    scheme,
    redacted: value.length ? `${value.slice(0, 2)}***` : '<空>',
    sha256_12: createHash('sha256').update(value).digest('hex').slice(0, 12),
    length: value.length,
  };
}

function startFakeCf(opts = {}) {  const zoneId = opts.zoneId || 'a'.repeat(32);
  const zoneName = opts.zoneName || 'example-zone.test';
  const state = {
    zone: { id: zoneId, name: zoneName },
    entrypoint: {
      id: 'ep-' + '1'.repeat(12),
      name: 'zone-level phase entry point',
      description: 'Zone-level phase entry point',
      kind: 'zone',
      phase: PHASE,
      version: '1',
      rules: JSON.parse(JSON.stringify(opts.rules || [])),
    },
  };
  const requests = [];
  const faults = new Map(); // key: 'all' | 'GET' | 'PUT' → 故障模式

  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://127.0.0.1');
      let body = null;
      if (raw) {
        try {
          body = JSON.parse(raw);
        } catch {
          body = { __unparsable: raw.slice(0, 100) };
        }
      }
      requests.push({
        method: req.method,
        path: url.pathname,
        query: url.search,
        auth: describeAuthHeader(req.headers.authorization),
        body,
      });

      const reply = (status, payload) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      };

      const fault = faults.get(req.method) || faults.get('all');
      if (fault === 'drop') return res.socket.destroy();
      if (fault === 'echo-token') {
        /* 最坏情况：服务端把 Authorization 的值回显进错误信息 —— 打印时必须已脱敏 */
        const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
        return reply(400, {
          success: false,
          errors: [{ code: 6003, message: `Invalid request headers (authorization=${token})` }],
          result: null,
        });
      }
      if (fault && FAULT_PAYLOADS[fault]) return reply(FAULT_PAYLOADS[fault].status, FAULT_PAYLOADS[fault].body);

      /* /user/tokens/verify */
      if (url.pathname === '/client/v4/user/tokens/verify') {
        return reply(200, { result: { id: 'tok-fake', status: 'active' }, success: true, errors: [], messages: [] });
      }

      /* /zones?name= */
      if (url.pathname === '/client/v4/zones') {
        const name = url.searchParams.get('name');
        const ok = name === zoneName;
        return reply(200, {
          result: ok ? [{ id: zoneId, name: zoneName, status: 'active' }] : [],
          success: true,
          errors: [],
          messages: [],
        });
      }

      /* entrypoint GET / PUT */
      if (url.pathname.endsWith(`/rulesets/phases/${PHASE}/entrypoint`)) {
        if (url.pathname.split('/')[4] !== zoneId) {
          return reply(404, { result: null, success: false, errors: [{ code: 7003, message: 'route not found' }], messages: [] });
        }
        if (req.method === 'GET') {
          return reply(200, { result: state.entrypoint, success: true, errors: [], messages: [] });
        }
        if (req.method === 'PUT') {
          if (!body || !Array.isArray(body.rules)) {
            return reply(400, { result: null, success: false, errors: [{ code: 10001, message: 'rules 缺失' }], messages: [] });
          }
          /* 全量覆盖语义：只补一个 id，不额外加字段，便于测试逐字比对 */
          state.entrypoint = {
            ...state.entrypoint,
            version: String(Number(state.entrypoint.version || '0') + 1),
            rules: body.rules.map((r, i) => ({ ...r, id: r.id || `rule-new-${i + 1}` })),
          };
          return reply(200, { result: state.entrypoint, success: true, errors: [], messages: [] });
        }
      }

      return reply(404, { result: null, success: false, errors: [{ code: 7003, message: `未实现：${url.pathname}` }], messages: [] });
    });
  });

  return new Promise((r) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      r({
        baseUrl: `http://127.0.0.1:${port}/client/v4`,
        port,
        zoneId,
        zoneName,
        state,
        requests,
        setFault: (target, mode) => faults.set(target, mode),
        clearFaults: () => faults.clear(),
        close: () => new Promise((done) => {
          server.close(() => done());
          server.closeAllConnections?.();
        }),
      });
    });
  });
}

/* ------------------------------------------------------------------ *
 * 测试脚手架
 * ------------------------------------------------------------------ */

let caseNo = 0;
function tmpDir(name) {
  const p = join(OUT_ROOT, `${name}-${process.pid}-${++caseNo}`);
  mkdirSync(p, { recursive: true });
  return p;
}

/** 捕获输出（测试里绝不直接打到真实 stdout） */
function recorder() {
  const lines = [];
  return {
    lines,
    log: (...a) => lines.push(a.join(' ')),
    errLog: (...a) => lines.push(a.join(' ')),
    text: () => lines.join('\n'),
  };
}

const ENV = { CLOUDFLARE_API_TOKEN: TOKEN };

/** 跑一次 CLI，返回 {code, text, lines} */
async function deploy(argv, { env = ENV, cwd = REPO } = {}) {
  const rec = recorder();
  const code = await runDeploy(argv, { env, cwd, log: rec.log, errLog: rec.errLog });
  return { code, text: rec.text(), lines: rec.lines };
}

/** 递归收集目录下所有文件内容（用于「令牌不落盘」的全目录扫描） */
function readAllFiles(dir) {
  if (!existsSync(dir)) return '';
  let acc = '';
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) acc += readAllFiles(p);
    else acc += readFileSync(p, 'utf8');
  }
  return acc;
}

const foreignRule = {
  id: 'rule-foreign-0001',
  action: 'rewrite',
  description: 'legacy: site tag（不是本工具的规则）',
  expression: 'true',
  action_parameters: { headers: { 'X-Site-Tag': { operation: 'set', value: 'prod' } } },
};

const oldManagedRule = {
  id: 'rule-hf-0001',
  action: 'rewrite',
  description: `${MANAGED_PREFIX}set-response-headers`,
  expression: 'true',
  action_parameters: { headers: { 'X-Content-Type-Options': { operation: 'set', value: 'nosniff' } } },
};

after(() => {
  rmSync(OUT_ROOT, { recursive: true, force: true });
});

/* ================================================================== *
 * 一、脱敏
 * ================================================================== */

test('redactSecret：只留前 2 位 + ***，空值有明确形态', () => {
  assert.equal(redactSecret(TOKEN), 'cf***');
  assert.equal(redactSecret('ab'), 'ab***');
  assert.equal(redactSecret(''), '<空>');
  assert.equal(redactSecret(null), '<空>');
});

test('fingerprintSecret：稳定、12 位十六进制、不同值不同哈希', () => {
  const a = fingerprintSecret(TOKEN);
  assert.match(a, /^sha256:[0-9a-f]{12}$/);
  assert.equal(a, fingerprintSecret(TOKEN));
  assert.notEqual(a, fingerprintSecret(TOKEN + 'x'));
});

test('scrubSecrets：文本里出现的令牌被抹成脱敏形态，短串不误伤', () => {
  const text = `Authorization: Bearer ${TOKEN} failed`;
  const scrubbed = scrubSecrets(text, [TOKEN]);
  assert.ok(!scrubbed.includes(TOKEN));
  assert.match(scrubbed, /Bearer cf\*\*\* failed/);
  /* 太短的值（<8）不参与替换，否则会把正常文本一起改坏 */
  assert.equal(scrubSecrets('abc def', ['ab']), 'abc def');
});

test('scrubSecrets：能抹掉「去掉不可见字符后」的形态（历史故障的粘贴形态）', () => {
  const dirty = `cfut_\u200b${'A'.repeat(30)}`;
  const text = `echoed: ${dirty.replace(/[^\x20-\x7e]/g, '')}`;
  const scrubbed = scrubSecrets(text, [dirty]);
  assert.ok(!scrubbed.includes('cfut_' + 'A'.repeat(30)));
});

/* ================================================================== *
 * 二、令牌自检（本地形态体检）
 * ================================================================== */

test('inspectToken：带前缀的新格式与 40 位旧格式都放行', () => {
  const a = inspectToken(TOKEN);
  assert.equal(a.ok, true);
  assert.equal(a.format, 'scannable');
  assert.equal(a.present, true);
  const b = inspectToken(LEGACY_TOKEN);
  assert.equal(b.ok, true);
  assert.equal(b.format, 'legacy');
});

test('inspectToken：粘成网址 → 阻断，并指出是网址', () => {
  const r = inspectToken('https://dash.cloudflare.com/profile/api-tokens');
  assert.equal(r.ok, false);
  assert.match(r.blocking.join(' '), /http\(s\):\/\//);
  assert.ok(r.markers.length > 0);
});

test('inspectToken：粘成命令文本 → 阻断（本项目历史上真实发生两次）', () => {
  const r = inspectToken('curl "https://api.cloudflare.com/client/v4/user/tokens/verify" -H "Authorization: Bearer xxx"');
  assert.equal(r.ok, false);
  assert.match(r.blocking.join(' '), /命令名|网址|:\/\//);
});

test('inspectToken：零宽空格 / BOM 等不可见字符 → 阻断并给出码点', () => {
  const r = inspectToken(`cfut_${'A'.repeat(20)}\u200bB`);
  assert.equal(r.ok, false);
  assert.deepEqual(r.nonPrintableHex, ['U+200B']);
  assert.match(r.blocking.join(' '), /不可打印/);
});

test('inspectToken：值里带空格或 Bearer 前缀 → 阻断（都会导致 6111）', () => {
  assert.equal(inspectToken('cfut_aaaa bbbb cccc dddd eeee ffff').ok, false);
  const bearer = inspectToken(`Bearer ${TOKEN}`);
  assert.equal(bearer.ok, false);
  assert.match(bearer.blocking.join(' '), /Bearer/);
});

test('inspectToken：别的平台凭据 → 阻断并指名道姓', () => {
  const r = inspectToken('ghp_' + 'x'.repeat(36));
  assert.equal(r.ok, false);
  assert.match(r.blocking.join(' '), /GitHub/);
});

test('inspectToken：格式不认识**不**阻断 —— 格式假设会过时，最终判定权交给 API', () => {
  const r = inspectToken('Zx9-not-a-known-format-at-all-2026');
  assert.equal(r.ok, true);
  assert.equal(r.format, 'unknown');
  assert.match(r.warnings.join(' '), /verify-token/);
});

test('inspectToken：返回值里不含令牌原文', () => {
  const r = inspectToken(TOKEN);
  assert.ok(!JSON.stringify(r).includes(TOKEN));
  assert.equal(r.redacted, 'cf***');
  assert.match(r.fingerprint, /^sha256:[0-9a-f]{12}$/);
});

test('inspectToken：未设置时 present=false 且给出可执行提示', () => {
  const r = inspectToken('');
  assert.equal(r.present, false);
  assert.equal(r.ok, false);
  assert.match(r.blocking.join(' '), /CLOUDFLARE_API_TOKEN/);
});

/* ================================================================== *
 * 三、策略 → 规则体 / 合并
 * ================================================================== */

test('buildRulesetRules：每个策略头一条 set，remove 清单一条 remove，顺序确定', () => {
  const rules = buildRulesetRules(policy);
  assert.equal(rules.length, 2);
  assert.equal(rules[0].description, `${MANAGED_PREFIX}set-response-headers`);
  assert.equal(rules[0].action, 'rewrite');
  assert.equal(rules[0].expression, 'true');
  assert.deepEqual(Object.keys(rules[0].action_parameters.headers), Object.keys(policy.headers));
  for (const [name, spec] of Object.entries(policy.headers)) {
    assert.deepEqual(rules[0].action_parameters.headers[name], { operation: 'set', value: spec.value });
  }
  assert.equal(rules[1].description, `${MANAGED_PREFIX}remove-response-headers`);
  assert.deepEqual(Object.keys(rules[1].action_parameters.headers), policy.remove);
  for (const name of policy.remove) {
    assert.deepEqual(rules[1].action_parameters.headers[name], { operation: 'remove' });
  }
});

test('buildRulesetRules：expression 可覆盖（用于按路径收窄）', () => {
  const rules = buildRulesetRules(policy, { expression: 'starts_with(http.request.uri.path, "/app")' });
  assert.equal(rules[0].expression, 'starts_with(http.request.uri.path, "/app")');
});

test('buildRulesetRules：空 remove 不产生空规则', () => {
  const rules = buildRulesetRules({ headers: { 'X-A': { value: '1' } }, remove: [] });
  assert.equal(rules.length, 1);
});

test('planMerge：别人的规则原样保留、本工具规则被替换、本工具在后', () => {
  const managedNew = buildRulesetRules(policy);
  const m = planMerge([foreignRule, oldManagedRule], managedNew);
  assert.equal(m.keptForeign, 1);
  assert.equal(m.replacedManaged, 1);
  assert.deepEqual(m.rules[0], foreignRule);
  assert.deepEqual(m.rules.slice(1), managedNew);
});

test('planMerge：不允许把别人的规则静默丢掉（这是本工具最要紧的安全属性）', () => {
  const many = [foreignRule, { ...foreignRule, id: 'f2', description: 'another: rule' }, oldManagedRule];
  const m = planMerge(many, buildRulesetRules(policy));
  assert.equal(m.keptForeign, 2);
  assert.deepEqual(m.rules.slice(0, 2), many.slice(0, 2));
});

/* ================================================================== *
 * 四、错误码诊断
 * ================================================================== */

test('flattenErrors：摊平 error_chain', () => {
  const flat = flattenErrors([{ code: 6003, message: 'x', error_chain: [{ code: 6111, message: 'y' }] }]);
  assert.deepEqual(flat.map((e) => e.code), [6003, 6111]);
});

test('collectApiErrors：旧的顶层错误体（本项目历史上真收到的那一份）也要认出来', () => {
  const legacy = { code: 6003, message: 'Invalid request headers', error_chain: [{ code: 6111, message: 'Invalid format for Authorization header' }] };
  assert.deepEqual(collectApiErrors(legacy).map((e) => e.code), [6003]);
  assert.deepEqual(flattenErrors(collectApiErrors(legacy)).map((e) => e.code), [6003, 6111]);
  assert.deepEqual(collectApiErrors({ success: true, result: {} }), []);
  assert.deepEqual(collectApiErrors(null), []);
  assert.deepEqual(
    collectApiErrors({ success: false, errors: [{ code: 10000, message: 'Authentication error' }] }).map((e) => e.code),
    [10000]
  );
});

test('diagnoseApiFailure：四个必需错误码各归各位', () => {
  assert.equal(diagnoseApiFailure(401, [{ code: 10000, message: 'Authentication error' }]).level, 'auth');
  assert.equal(diagnoseApiFailure(403, [{ code: 9109, message: 'Unauthorized' }]).level, 'permission');
  assert.match(diagnoseApiFailure(403, []).hint, /Transform Rules Edit/);
  const hf = diagnoseApiFailure(400, [{ code: 6003, message: 'Invalid request headers', error_chain: [{ code: 6111, message: 'Invalid format for Authorization header' }] }]);
  assert.equal(hf.level, 'header-format');
  assert.match(hf.hint, /不可见字符|命令文本/);
  assert.equal(diagnoseApiFailure(400, [{ code: 9106, message: 'Missing X-Auth-Email header' }]).level, 'legacy-auth');
});

test('diagnoseApiFailure：未归类状态不会被硬套成已知结论', () => {
  assert.equal(diagnoseApiFailure(404, [{ code: 7003, message: 'not found' }]).level, 'not-found');
  assert.equal(diagnoseApiFailure(429, []).level, 'rate-limit');
  assert.equal(diagnoseApiFailure(503, []).level, 'server');
  assert.equal(diagnoseApiFailure(418, []).level, 'unknown');
});

/* ================================================================== *
 * 五、dry-run
 * ================================================================== */

test('dry-run：一个请求都不发、不落盘，但把将要发的请求全打出来', async () => {
  const fake = await startFakeCf({ rules: [foreignRule, oldManagedRule] });
  const out = join(tmpDir('dry'), 'out');
  try {
    const r = await deploy(['--zone', fake.zoneName, '--out', out, '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_OK);
    assert.equal(fake.requests.length, 0, 'dry-run 期间假服务收到的请求必须为 0');
    assert.equal(existsSync(out), false, 'dry-run 不该创建任何输出目录');

    assert.match(r.text, new RegExp(`GET ${fake.baseUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/zones\\?name=example-zone\\.test`));
    assert.match(r.text, /GET .*\/rulesets\/phases\/http_response_headers_transform\/entrypoint/);
    assert.match(r.text, /PUT .*\/rulesets\/phases\/http_response_headers_transform\/entrypoint/);
    assert.match(r.text, /DRY-RUN/);
    /* body 就是策略渲染出来的规则体 */
    assert.ok(r.text.includes(`"${MANAGED_PREFIX}set-response-headers"`));
    assert.ok(r.text.includes(`"Content-Security-Policy"`));
    assert.ok(r.text.includes('"operation": "remove"'));
  } finally {
    await fake.close();
  }
});

test('dry-run 默认生效：不加任何模式参数也是 dry-run', async () => {
  const fake = await startFakeCf();
  try {
    const r = await deploy(['--zone', fake.zoneId, '--base-url', fake.baseUrl, '--out', join(tmpDir('dry2'), 'out')]);
    assert.equal(r.code, EXIT_OK);
    assert.equal(fake.requests.length, 0);
    assert.match(r.text, /DRY-RUN（不发任何请求）/);
  } finally {
    await fake.close();
  }
});

test('dry-run --from-snapshot：预览的 PUT body 与 apply 实际发出的一字不差', async () => {
  const fake = await startFakeCf({ rules: [foreignRule, oldManagedRule] });
  const base = tmpDir('fromsnap');
  try {
    const applied = await deploy(['--zone', fake.zoneId, '--apply', '--out', join(base, 'out'), '--base-url', fake.baseUrl]);
    assert.equal(applied.code, EXIT_OK);
    const snapFile = join(base, 'out', readdirSync(join(base, 'out'))[0]);
    const actualBody = fake.requests.find((x) => x.method === 'PUT').body;

    fake.requests.length = 0;
    const preview = await deploy(['--zone', fake.zoneId, '--dry-run', '--from-snapshot', snapFile, '--out', join(base, 'out'), '--base-url', fake.baseUrl]);
    assert.equal(preview.code, EXIT_OK);
    assert.equal(fake.requests.length, 0, '预演也必须 0 请求');

    const printed = preview.text.slice(preview.text.indexOf('"rules"'));
    for (const rule of actualBody.rules) {
      assert.ok(printed.includes(rule.description), `预览里应含 ${rule.description}`);
    }
    assert.match(preview.text, /保留别人的规则 1 条/);
  } finally {
    await fake.close();
  }
});

test('dry-run 与 --apply 同时给 → 拒绝（不允许含混地改线上）', async () => {
  const r = await deploy(['--zone', 'a'.repeat(32), '--dry-run', '--apply']);
  assert.equal(r.code, EXIT_LOCAL_ERROR);
  assert.match(r.text, /互斥/);
});

/* ================================================================== *
 * 六、apply
 * ================================================================== */

test('apply：先 GET 再 PUT，PUT body = 别人的规则 + 策略规则，且先落快照', async () => {
  const fake = await startFakeCf({ rules: [foreignRule, oldManagedRule] });
  const out = join(tmpDir('apply'), 'out');
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', out, '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_OK);

    assert.deepEqual(fake.requests.map((x) => x.method), ['GET', 'PUT'], '顺序必须是先读现状、再覆盖');
    assert.match(fake.requests[0].path, new RegExp(`/zones/${fake.zoneId}/rulesets/phases/${PHASE}/entrypoint$`));

    const expected = { rules: [foreignRule, ...buildRulesetRules(policy)] };
    assert.deepEqual(fake.requests[1].body, expected);

    /* 服务端最终状态：别人的规则还在，本工具规则换成新的 */
    const after1 = fake.state.entrypoint.rules;
    assert.equal(after1.length, 3);
    assert.deepEqual(after1[0], foreignRule);
    assert.equal(after1[1].description, `${MANAGED_PREFIX}set-response-headers`);
    assert.equal(after1[2].description, `${MANAGED_PREFIX}remove-response-headers`);

    /* 快照：内容就是 apply 之前的现状 */
    const files = readdirSync(out).filter((f) => f.startsWith('cf-ruleset-before-'));
    assert.equal(files.length, 1);
    const snap = JSON.parse(readFileSync(join(out, files[0]), 'utf8'));
    assert.deepEqual(snap.entrypoint.rules, [foreignRule, oldManagedRule]);
    assert.equal(snap.zone.id, fake.zoneId);
    assert.equal(snap.phase, PHASE);
    assert.equal(snap.baseUrl, fake.baseUrl);

    /* 输出里给出可直接粘贴的回滚命令 */
    assert.match(r.text, /--rollback/);
    assert.match(r.text, /规则：2 条 → 3 条/);
  } finally {
    await fake.close();
  }
});

test('apply：按 zone 名先解析 zone id（GET /zones 那一步不能省）', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  try {
    const r = await deploy(['--zone', fake.zoneName, '--apply', '--out', join(tmpDir('applyname'), 'out'), '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_OK);
    assert.deepEqual(fake.requests.map((x) => x.method), ['GET', 'GET', 'PUT']);
    assert.match(fake.requests[0].query, /name=example-zone\.test/);
    assert.match(fake.requests[2].path, new RegExp(`/zones/${fake.zoneId}/`));
  } finally {
    await fake.close();
  }
});

test('snapshotFileName：时间戳进名字，两次调用不重名（旧快照不会被覆盖）', () => {
  const a = snapshotFileName(new Date('2026-09-17T01:02:03.456Z'));
  const b = snapshotFileName(new Date('2026-09-17T01:02:03.457Z'));
  assert.equal(a, 'cf-ruleset-before-2026-09-17T01-02-03-456Z.json');
  assert.notEqual(a, b);
});

/* ================================================================== *
 * 七、rollback
 * ================================================================== */

test('rollback：apply 新规则后还原，服务端最终状态与快照逐字一致（前后对照）', async () => {
  const fake = await startFakeCf({ rules: [foreignRule, oldManagedRule] });
  const base = tmpDir('rollback');
  const out = join(base, 'out');
  try {
    const app = await deploy(['--zone', fake.zoneId, '--apply', '--out', out, '--base-url', fake.baseUrl]);
    assert.equal(app.code, EXIT_OK);
    const afterApply = JSON.parse(JSON.stringify(fake.state.entrypoint.rules));
    assert.equal(afterApply.length, 3, 'apply 之后是「别人的 1 条 + 本工具 2 条」');

    const snapFile = join(out, readdirSync(out)[0]);

    /* 先 dry-run 预览：不发请求 */
    const n = fake.requests.length;
    const dry = await deploy(['--rollback', snapFile, '--zone', fake.zoneId, '--base-url', fake.baseUrl, '--out', out]);
    assert.equal(dry.code, EXIT_OK);
    assert.equal(fake.requests.length, n, '回滚预览不得发请求');
    assert.match(dry.text, /DRY-RUN/);

    /* 真回滚 */
    const rb = await deploy(['--rollback', snapFile, '--zone', fake.zoneId, '--apply', '--base-url', fake.baseUrl, '--out', out]);
    assert.equal(rb.code, EXIT_OK);

    const finalRules = fake.state.entrypoint.rules;
    assert.deepEqual(finalRules, [foreignRule, oldManagedRule], '回滚后必须与快照逐字一致');
    assert.notDeepEqual(finalRules, afterApply, '回滚前后确实不同（否则这条测试没测到东西）');
    assert.deepEqual(fake.requests[fake.requests.length - 1].body, { rules: [foreignRule, oldManagedRule] });
  } finally {
    await fake.close();
  }
});

test('rollback：--zone 与快照里的 zone 不一致 → 拒绝（不许把 A 区配置还原到 B 区）', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  const out = join(tmpDir('rollbackzone'), 'out');
  try {
    await deploy(['--zone', fake.zoneId, '--apply', '--out', out, '--base-url', fake.baseUrl]);
    const snapFile = join(out, readdirSync(out)[0]);
    const n = fake.requests.length;
    const r = await deploy(['--rollback', snapFile, '--zone', 'b'.repeat(32), '--apply', '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_LOCAL_ERROR);
    assert.match(r.text, /拒绝/);
    assert.equal(fake.requests.length, n);
  } finally {
    await fake.close();
  }
});

test('rollback：快照文件不存在 / 不是快照 → 退出 2，不发请求', async () => {
  const fake = await startFakeCf();
  const dir = tmpDir('rollbackbad');
  try {
    const missing = await deploy(['--rollback', join(dir, 'nope.json'), '--apply', '--base-url', fake.baseUrl]);
    assert.equal(missing.code, EXIT_LOCAL_ERROR);
    assert.match(missing.text, /不存在/);
    assert.equal(fake.requests.length, 0);
  } finally {
    await fake.close();
  }
});

/* ================================================================== *
 * 八、故障注入：安全失败
 * ================================================================== */

test('故障 401（全端点）：退出码 1，不落快照、不动线上', async () => {
  const fake = await startFakeCf({ rules: [foreignRule, oldManagedRule] });
  const out = join(tmpDir('f401'), 'out');
  fake.setFault('all', '401');
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', out, '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_REMOTE_REJECT);
    assert.equal(existsSync(out), false, '没读到现状就不该有快照');
    assert.equal(fake.requests.some((x) => x.method === 'PUT'), false);
    assert.match(r.text, /认证失败/);
    assert.deepEqual(fake.state.entrypoint.rules, [foreignRule, oldManagedRule]);
  } finally {
    await fake.close();
  }
});

test('故障 403（PUT 阶段）：退出码 1、线上状态不变、快照保留、给出回滚命令', async () => {
  const fake = await startFakeCf({ rules: [foreignRule, oldManagedRule] });
  const out = join(tmpDir('f403'), 'out');
  fake.setFault('PUT', '403');
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', out, '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_REMOTE_REJECT);
    assert.match(r.text, /权限不足/);
    assert.deepEqual(fake.state.entrypoint.rules, [foreignRule, oldManagedRule], 'PUT 被拒后线上必须还是原样');
    assert.equal(readdirSync(out).filter((f) => f.startsWith('cf-ruleset-before-')).length, 1);
    assert.match(r.text, /--rollback/);
  } finally {
    await fake.close();
  }
});

test('故障 9106（PUT 阶段）：识别为旧式鉴权路径问题并退出 1', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  fake.setFault('PUT', '9106');
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', join(tmpDir('f9106'), 'out'), '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_REMOTE_REJECT);
    assert.match(r.text, /9106|旧式鉴权|认证头/);
    assert.deepEqual(fake.state.entrypoint.rules, [foreignRule]);
  } finally {
    await fake.close();
  }
});

test('故障 6111（PUT 阶段）：判定为「Authorization 头格式非法」而不是「令牌无效」', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  fake.setFault('PUT', '6111');
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', join(tmpDir('f6111'), 'out'), '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_REMOTE_REJECT);
    assert.match(r.text, /Authorization 头格式非法/);
    assert.match(r.text, /不可见字符|网址或命令文本/);
    assert.ok(r.text.includes('6003'));
    assert.deepEqual(fake.state.entrypoint.rules, [foreignRule]);
  } finally {
    await fake.close();
  }
});

test('故障 连接断开（GET 阶段）：退出码 2，并明确提示「断开不等于没改」', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  fake.setFault('all', 'drop');
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', join(tmpDir('fdrop'), 'out'), '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_LOCAL_ERROR);
    assert.match(r.text, /没能完成|ECONNRESET/);
    assert.match(r.text, /不等于|可能已经/);
    assert.equal(fake.requests.some((x) => x.method === 'PUT'), false);
  } finally {
    await fake.close();
  }
});

test('zone 名解析不出来 → 退出 2 并提醒「权限不足会返回空列表而不是 403」', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  try {
    const r = await deploy(['--zone', 'not-my-zone.test', '--apply', '--out', join(tmpDir('fzone'), 'out'), '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_LOCAL_ERROR);
    assert.match(r.text, /没找到名为|Zone Read/);
    assert.equal(fake.requests.some((x) => x.method === 'PUT'), false);
  } finally {
    await fake.close();
  }
});

/* ================================================================== *
 * 九、令牌：缺失 / 形态非法 / 不落盘
 * ================================================================== */

test('无令牌 + --apply：安全失败（退出 2），说明只从环境变量读，且不发任何请求', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', join(tmpDir('notoken'), 'out'), '--base-url', fake.baseUrl], { env: {} });
    assert.equal(r.code, EXIT_LOCAL_ERROR);
    assert.match(r.text, /未设置 CLOUDFLARE_API_TOKEN/);
    assert.match(r.text, /不接受命令行传参/);
    assert.equal(fake.requests.length, 0);
  } finally {
    await fake.close();
  }
});

test('无令牌 + dry-run：照常预览（退出 0），并在输出里标明令牌未设置', async () => {
  const fake = await startFakeCf();
  try {
    const r = await deploy(['--zone', fake.zoneId, '--dry-run', '--out', join(tmpDir('notokendry'), 'out'), '--base-url', fake.baseUrl], { env: {} });
    assert.equal(r.code, EXIT_OK);
    assert.match(r.text, /未设置 CLOUDFLARE_API_TOKEN/);
    assert.equal(fake.requests.length, 0);
  } finally {
    await fake.close();
  }
});

test('令牌存的是网址/命令文本：本地就拦下（退出 2），不发请求，也不回显原文', async () => {
  const fake = await startFakeCf();
  const junk = 'curl "https://api.cloudflare.com/client/v4/user/tokens/verify"';
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', join(tmpDir('junk'), 'out'), '--base-url', fake.baseUrl], {
      env: { CLOUDFLARE_API_TOKEN: junk },
    });
    assert.equal(r.code, EXIT_LOCAL_ERROR);
    assert.equal(fake.requests.length, 0);
    assert.ok(!r.text.includes(junk), '命令文本原文不得出现在输出里');
    assert.ok(r.text.includes('cu***'), '只留前 2 位 + ***');
  } finally {
    await fake.close();
  }
});

test('令牌不落盘：apply 全流程后，所有产物 / 请求记录 / 输出里都没有令牌明文', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  const out = join(tmpDir('noleak'), 'out');
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', out, '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_OK);

    const onDisk = readAllFiles(out);
    assert.ok(onDisk.length > 0, '快照确实写出来了（否则这条断言是空转）');
    assert.ok(!onDisk.includes(TOKEN), '快照/产物里不得出现令牌明文');

    assert.ok(!r.text.includes(TOKEN), '输出里不得出现令牌明文');
    assert.ok(r.text.includes(describeSecret(TOKEN)), '但仍要能关联：脱敏形态 + 哈希');
    assert.ok(r.text.includes(fingerprintSecret(TOKEN)));

    const wire = JSON.stringify(fake.requests);
    assert.ok(!wire.includes(TOKEN), '请求侧的记录里也不该有明文（假服务只存脱敏形态）');
    /* 但必须能证明「令牌确实以 Bearer 明文发出去了」—— 用哈希关联，而不是靠打印原文 */
    assert.equal(fake.requests[0].auth.scheme, 'Bearer');
    assert.equal(fake.requests[0].auth.redacted, 'cf***');
    assert.equal(fake.requests[0].auth.sha256_12, fingerprintSecret(TOKEN).replace('sha256:', ''));
  } finally {
    await fake.close();
  }
});

test('服务端把令牌回显进错误信息时，输出里也只剩脱敏形态', async () => {
  const fake = await startFakeCf({ rules: [foreignRule] });
  fake.setFault('all', 'echo-token');
  try {
    const r = await deploy(['--zone', fake.zoneId, '--apply', '--out', join(tmpDir('echo'), 'out'), '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_REMOTE_REJECT);
    assert.ok(!r.text.includes(TOKEN), '回显的令牌必须在打印前被抹掉');
    assert.match(r.text, /authorization=cf\*\*\*/);
  } finally {
    await fake.close();
  }
});

/* ================================================================== *
 * 十、--verify-token
 * ================================================================== */

test('--verify-token：打到 /user/tokens/verify，退出 0，并声明它不能证明下发权限', async () => {
  const fake = await startFakeCf();
  try {
    const r = await deploy(['--verify-token', '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_OK);
    assert.equal(fake.requests.length, 1);
    assert.equal(fake.requests[0].path, '/client/v4/user/tokens/verify');
    assert.match(r.text, /令牌有效/);
    assert.match(r.text, /不能.*证明|不看权限范围/);
    assert.ok(!r.text.includes(TOKEN));
  } finally {
    await fake.close();
  }
});

test('--verify-token + 401：退出 1 并给出「先跑自检、再核对清单」的处置', async () => {
  const fake = await startFakeCf();
  fake.setFault('all', '401');
  try {
    const r = await deploy(['--verify-token', '--base-url', fake.baseUrl]);
    assert.equal(r.code, EXIT_REMOTE_REJECT);
    assert.match(r.text, /认证失败/);
    assert.ok(!r.text.includes(TOKEN));
  } finally {
    await fake.close();
  }
});

test('--verify-token 无令牌：退出 2，不发请求', async () => {
  const fake = await startFakeCf();
  try {
    const r = await deploy(['--verify-token', '--base-url', fake.baseUrl], { env: {} });
    assert.equal(r.code, EXIT_LOCAL_ERROR);
    assert.equal(fake.requests.length, 0);
  } finally {
    await fake.close();
  }
});

/* ================================================================== *
 * 十一、默认基址（防止测试/自证悄悄指向真实 API）
 * ================================================================== */

test('默认 base URL 是真实 API 地址：离线验证必须显式覆盖它', () => {
  assert.equal(DEFAULT_BASE_URL, 'https://api.cloudflare.com/client/v4');
});

test('buildDeployPlan：zone id 给出时不需要 /zones 那一步；zone 名给出时必须有', () => {
  const withId = buildDeployPlan({ baseUrl: 'http://127.0.0.1:1', zone: 'a'.repeat(32), managedRules: [] });
  assert.deepEqual(withId.map((r) => r.method), ['GET', 'PUT']);
  const withName = buildDeployPlan({ baseUrl: 'http://127.0.0.1:1', zone: 'example.test', managedRules: [] });
  assert.deepEqual(withName.map((r) => r.method), ['GET', 'GET', 'PUT']);
  assert.match(withName[1].url, /<zone-id>/);
});

test('临时产物目录确实写了东西但不是空目录（校准「没落盘」类断言的灵敏度）', () => {
  const dir = tmpDir('sanity');
  const f = join(dir, 'x.txt');
  writeFileSync(f, 'hello', 'utf8');
  assert.ok(readAllFiles(dir).includes('hello'));
  assert.ok(statSync(dir).isDirectory());
});
