#!/usr/bin/env node
/**
 * header-forge 命令行入口
 *
 * 五个子命令：
 *   generate  用策略生成各平台配置
 *   import    从现有配置反向导入，生成策略草稿（接管别人的项目时用）
 *   verify    校验线上响应头是否与策略一致
 *   advise    分析页面并给出不会破坏站点的 CSP 建议
 *   simulate  用生成的配置文件起本地服务并自校验（证明配置有效）
 *
 * 退出码：0 = 通过；1 = 校验不一致/现状不合规（可作 CI 门禁）；2 = 运行错误
 *
 * @module index
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { loadPolicy, PolicyError, summarizePolicy, collectPolicyProblems } from './lib/policy.mjs';
import { generateAll, GENERATOR_IDS, planOutputPaths } from './generators/index.mjs';
import { analyzeImport, IMPORT_FORMATS, SECURITY_HEADERS } from './importer.mjs';
import { verifyUrl } from './verify.mjs';
import { analyzePage, suggestCsp, checkHashDrift } from './advise.mjs';
import { startSimulator } from './simulate.mjs';
import { renderMarkdown, renderJson, renderSummary } from './lib/report.mjs';
import { request } from './lib/http.mjs';

const VERSION = '0.1.0';

const HELP = `
header-forge v${VERSION} —— 安全响应头配置即代码（零依赖）

用法：node src/index.mjs <子命令> [选项]

子命令：
  generate    用策略生成各平台配置
  import      从现有配置反向导入，生成策略草稿
  verify      校验线上响应头是否与策略一致
  advise      分析页面并给出 CSP 建议
  simulate    用生成的配置文件起本地服务并自校验

通用选项：
  --policy <路径>     策略文件（默认 headers.policy.json）
  --out <目录/文件>   输出目录（generate）或输出文件（import）

generate 选项：
  --only <生成器>     只生成指定平台，逗号分隔
                      可选：${GENERATOR_IDS.join(', ')}

import 选项：
  --from <路径>       要导入的现有配置（_headers / vercel.json / nginx 片段 / Caddyfile）
  --format <格式>     指定格式，不给则自动识别：${IMPORT_FORMATS.join(' / ')}
  --out <路径>        输出策略文件（默认 headers.policy.imported.json）
  --all               连非安全响应头一起导入（默认只导入安全类，见下）
  --force             允许覆盖已存在的输出文件
  --stdout            把策略 JSON 打到标准输出，不写文件

  默认只导入安全响应头。原因：真实配置里 Cache-Control / Content-Type / Access-Control-*
  常按路径分别取值，而策略模型是一个头一个取值 —— 全量导入会压平差异，
  重新生成发布时就会替换掉原有的按路径规则。

verify 选项：
  --url <地址>        校验地址（默认取策略中第一个 target）

advise 选项：
  --url <地址>        要分析的页面地址
  --html <路径>       改为分析本地 HTML 文件（离线）
  --report-only       建议中提示先使用 Report-Only 模式

simulate 选项：
  --config <路径>     生成的配置文件（_headers 或 vercel.json）
  --port <端口>       监听端口（默认随机）

示例：
  node src/index.mjs generate --policy headers.policy.json --out dist
  node src/index.mjs import --from public/_headers
  node src/index.mjs import --from nginx.conf --format nginx --stdout
  node src/index.mjs verify --policy headers.policy.json
  node src/index.mjs simulate --config dist/_headers --policy headers.policy.json
`.trim();

function parseArgs(argv) {
  const args = { _: [] };
  const takesValue = new Set([
    '--policy', '--out', '--url', '--html', '--config', '--only', '--port', '--check', '--from', '--format',
  ]);

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (takesValue.has(token)) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) throw new Error(`${token} 需要一个值`);
      args[token.slice(2)] = value;
      i++;
    } else if (token.startsWith('--')) {
      args[token.slice(2)] = true;
    } else {
      args._.push(token);
    }
  }
  return args;
}

/* ============================ generate ============================ */

function cmdGenerate(args) {
  const policyPath = args.policy || 'headers.policy.json';
  const outDir = args.out || 'dist';

  const policy = loadPolicy(policyPath);
  const info = summarizePolicy(policy);
  console.log(`📋 策略：${info.headerCount} 个响应头（${policyPath}）`);

  const only = args.only ? String(args.only).split(',').map((s) => s.trim()).filter(Boolean) : null;
  const artifacts = generateAll(policy, { only });

  mkdirSync(outDir, { recursive: true });

  /* 落点由 planOutputPaths 统一决定 —— 不能靠遍历顺序，
     否则同名产物（Cloudflare Pages 与 Netlify 都叫 _headers）会互相静默覆盖。 */
  for (const { artifact, target, disambiguated } of planOutputPaths(outDir, artifacts)) {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, artifact.content, 'utf8');
    console.log(`  ✅ ${artifact.label.padEnd(18)} → ${target}`);
    if (disambiguated) {
      console.log(`     · 与前面某个平台的产物同名，已放进子目录以免互相覆盖`);
    }
    for (const note of artifact.notes || []) console.log(`     · ${note}`);
  }

  /* 生成清单，便于校验产物完整性 */
  writeFileSync(
    join(outDir, 'manifest.json'),
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        tool: `header-forge v${VERSION}`,
        policy: policyPath,
        artifacts: artifacts.map((a) => ({ id: a.id, label: a.label, filename: a.filename })),
      },
      null,
      2
    ) + '\n',
    'utf8'
  );

  console.log(`\n共生成 ${artifacts.length} 份配置 → ${outDir}/`);
  return 0;
}

/* ============================= import ============================= */

/**
 * 反向导入：把现有配置变成策略草稿
 *
 * 关键立场：**忠实反映现状，不顺手补齐**。导入出的策略可能不满足安全基线，
 * 那正是要展示给用户的差距 —— 如果导入时悄悄补上缺失的头，用户会以为站点
 * 已经有了这些防护，这是最危险的失败方式。
 *
 * 现状不合规时返回 1（与 verify 一致，可作 CI 门禁）。
 */
function cmdImport(args) {
  const fromPath = args.from;
  if (!fromPath) {
    throw new Error('需要 --from <路径>，指定要导入的现有配置文件');
  }
  if (!existsSync(fromPath)) {
    throw new Error(`文件不存在：${fromPath}`);
  }

  const text = readFileSync(fromPath, 'utf8');
  const result = analyzeImport(text, {
    format: args.format,
    filename: fromPath,
    include: args.all ? 'all' : 'security',
  });

  if (!result.ok) {
    console.error(`🛑 导入失败：${result.error}`);
    if (result.ignored?.length) {
      console.error('   被跳过的非安全响应头：');
      for (const i of result.ignored) console.error(`     · ${i.name}`);
    }
    if (result.skipped?.length) {
      console.error('   解析过程中跳过的内容：');
      for (const s of result.skipped) console.error(`     · [${s.where}] ${s.line}`);
    }
    return 2;
  }

  const { draft, gaps, imported } = result;

  console.log(`📥 反向导入：${fromPath}`);
  console.log(`   识别格式：${imported.format}`);
  console.log(`   解析出 ${imported.headerCount} 个响应头`);
  console.log('');

  for (const [name, value] of Object.entries(imported.headers)) {
    const shown = value.length > 72 ? value.slice(0, 69) + '…' : value;
    console.log(`   ${name}: ${shown}`);
  }
  if (imported.remove.length) {
    console.log('');
    console.log(`   删除指令：${imported.remove.join(', ')}`);
  }
  console.log('');

  if (imported.skipped.length) {
    console.log(`⚠️ 有 ${imported.skipped.length} 处内容无法解析（已保留在报告里，未静默丢弃）：`);
    for (const s of imported.skipped.slice(0, 10)) {
      console.log(`   · [${s.where}] ${s.line}`);
    }
    if (imported.skipped.length > 10) console.log(`   · …另有 ${imported.skipped.length - 10} 处`);
    console.log('');
  }

  if (imported.ignored && imported.ignored.length) {
    console.log(`ℹ️ 有 ${imported.ignored.length} 个响应头未接管（默认只导入安全类）：`);
    for (const i of imported.ignored) console.log(`   · ${i.name}`);
    console.log('');
    console.log('   为什么：这些头（如 Cache-Control）在真实配置里常按路径分别取值，');
    console.log('   而策略模型是一个头一个取值 —— 导进来会压平差异，');
    console.log('   一旦重新生成发布，就会替换掉你原有的按路径规则。');
    console.log('   它们留在原配置里即可。确实要全量导入请加 --all。');
    console.log('');
  }

  if (imported.warnings.length) {
    console.log('⚠️ 需要注意：');
    for (const w of imported.warnings) console.log(`   · ${w}`);
    console.log('');
  }

  if (gaps.length) {
    console.log(`🛑 现状与安全基线有 ${gaps.length} 处差距 —— 这份策略忠实反映了现状，因此它不满足基线：`);
    for (const g of gaps) console.log(`   · ${g}`);
    console.log('');
    console.log('   ⚠️ 导入不会替你补齐这些 —— 补齐意味着站点"看起来合规"但实际没这些头。');
    console.log('      请改好策略里对应的取值，再走 generate → simulate → 发布的流程。');
    console.log('');
  } else {
    console.log('✅ 现状已满足全部安全基线（导入的头与基线要求一致）');
    console.log('');
  }

  const json = JSON.stringify(draft, null, 2) + '\n';

  if (args.stdout) {
    process.stdout.write(json);
    return gaps.length ? 1 : 0;
  }

  const outPath = args.out || 'headers.policy.imported.json';
  if (existsSync(outPath) && !args.force) {
    console.error(`🛑 输出文件已存在：${outPath}`);
    console.error('   用 --force 覆盖，或改 --out 换个名字。');
    console.error('   （默认不覆盖：策略文件是人工改过的资产，误覆盖代价高）');
    return 2;
  }

  writeFileSync(outPath, json, 'utf8');
  console.log(`📄 策略草稿已写入：${outPath}`);
  console.log('');
  console.log('   下一步：');
  console.log(`     1. 打开 ${outPath}，把 why 字段从占位说明改成真实理由`);
  if (gaps.length) console.log('     2. 按上面的差距清单修掉缺失/过弱的头');
  console.log('     3. 改好后改名为 headers.policy.json，再跑 generate 与 simulate');
  console.log('');
  console.log('   注意：导入只恢复"头部名与取值"—— severity 与 why 是人的判断，');
  console.log('         配置里没有这些信息，所以导入时给了占位值。');

  return gaps.length ? 1 : 0;
}

/* ============================= verify ============================= */

async function cmdVerify(args) {
  const policyPath = args.policy || 'headers.policy.json';
  const outDir = args.out || 'out';
  const policy = loadPolicy(policyPath);

  const url = args.url || firstTarget(policy);
  if (!url) {
    throw new Error('未指定 --url，且策略中没有 targets 可用于推断地址');
  }

  console.log(`🔍 校验 ${url}`);
  const result = await verifyUrl(policy, url);

  if (!result.ok) {
    console.error(`\n🛑 无法获取响应：${result.error}`);
    return 2;
  }

  const meta = {
    version: VERSION,
    startedAt: result.startedAt,
    policyPath,
    status: result.meta.status,
    finalUrl: result.meta.finalUrl,
  };

  mkdirSync(outDir, { recursive: true });
  writeFileSync(
    join(outDir, 'conformance.md'),
    renderMarkdown({ policy, results: result.results, url, meta }),
    'utf8'
  );
  writeFileSync(
    join(outDir, 'conformance.json'),
    JSON.stringify(renderJson({ policy, results: result.results, url, meta }), null, 2),
    'utf8'
  );

  console.log('');
  console.log(renderSummary({ results: result.results }));
  console.log('');
  console.log(`📄 报告：${join(outDir, 'conformance.md')}`);

  const nonCompliant = result.results.some((r) => r.status === 'missing' || r.status === 'mismatch');
  return nonCompliant ? 1 : 0;
}

/**
 * 从策略中推断默认校验地址
 * 优先选标记了 primary: true 的目标 —— 策略里可能同时记录多个部署目标
 * （例如 GitHub Pages 预期不符合、Cloudflare Pages 必须符合）。
 */
function firstTarget(policy) {
  const entries = Object.entries(policy.targets || {});
  if (entries.length === 0) return null;

  const primary = entries.find(([, cfg]) => cfg && cfg.primary === true);
  const key = primary ? primary[0] : entries[0][0];
  return key.startsWith('http') ? key : `https://${key}/`;
}

/* ============================= advise ============================= */

async function cmdAdvise(args) {
  let html;
  let source;

  if (args.html) {
    html = readFileSync(args.html, 'utf8');
    source = args.html;
  } else {
    if (!args.url) throw new Error('需要 --url 或 --html');
    const res = await request(args.url, { method: 'GET', timeoutMs: 15000 });
    if (!res.ok) {
      console.error(`🛑 无法获取页面：${res.error}`);
      return 2;
    }
    html = res.body;
    source = res.finalUrl || args.url;
  }

  const analysis = analyzePage(html);
  const suggestion = suggestCsp(analysis, { reportOnly: true });

  console.log(`🧠 页面分析：${source}`);
  console.log(
    `   内联脚本 ${analysis.inlineScriptCount} 段 · 内联事件 ${analysis.eventHandlers} 处 · ` +
      `内联样式 ${analysis.inlineStyleCount} 段 · style 属性 ${analysis.styleAttributes} 处`
  );
  const thirdParty = analysis.origins['script-src'] || [];
  console.log(`   第三方脚本来源：${thirdParty.length ? thirdParty.join(', ') : '无'}`);
  console.log('');
  console.log('建议的 CSP（可直接粘进 headers.policy.json）：');
  console.log('');
  console.log(`Content-Security-Policy: ${suggestion.value}`);
  console.log('');

  if (analysis.inlineScripts.length) {
    console.log('🔑 内联脚本 hash（已包含在上面的 CSP 中）：');
    for (const s of analysis.inlineScripts) {
      console.log(`   '${s.hash}'`);
      console.log(`     来源片段：${s.preview}…`);
    }
    console.log('');
  }

  if (suggestion.warnings.length) {
    console.log('⚠️ 需要注意：');
    for (const w of suggestion.warnings) console.log(`   · ${w}`);
    console.log('');
  }
  if (suggestion.notes.length) {
    console.log('ℹ️ 提示：');
    for (const n of suggestion.notes) console.log(`   · ${n}`);
    console.log('');
  }

  /* 可选：检查策略里的 hash 是否已与页面脱节 */
  if (args.check) {
    const policy = loadPolicy(args.check);
    const drift = checkHashDrift(policy, analysis);
    console.log(`🔍 hash 一致性检查（对照 ${args.check}）：`);
    if (drift.reason) {
      console.log(`   ⚠️ ${drift.reason}`);
      return 0;
    }
    if (drift.consistent) {
      console.log('   ✅ 策略中的 hash 与页面当前内容一致');
      return 0;
    }
    if (drift.missingInPolicy.length) {
      console.log(`   ❌ 页面中存在策略未覆盖的内联脚本 hash：`);
      for (const h of drift.missingInPolicy) console.log(`      ${h}`);
    }
    if (drift.staleInPolicy.length) {
      console.log(`   ❌ 策略中残留了页面上已不存在的 hash（脚本已改动，策略过期）：`);
      for (const h of drift.staleInPolicy) console.log(`      ${h}`);
    }
    console.log('   → 请重新运行 advise 并更新策略中的 CSP');
    return 1;
  }

  return 0;
}

/* ============================ simulate ============================ */

async function cmdSimulate(args) {
  const configPath = args.config || 'dist/_headers';
  if (!existsSync(configPath)) {
    throw new Error(`配置文件不存在：${configPath}（请先运行 generate）`);
  }

  const configText = readFileSync(configPath, 'utf8');
  const policy = loadPolicy(args.policy || 'headers.policy.json');

  console.log(`🧪 用 ${basename(configPath)} 启动本地模拟服务…`);
  const sim = await startSimulator({ configText, port: args.port ? Number(args.port) : 0 });
  console.log(`   地址：${sim.url}`);
  console.log(`   从配置中解析出 ${Object.keys(sim.headers).length} 个响应头`);

  try {
    const result = await verifyUrl(policy, sim.url);
    if (!result.ok) {
      console.error(`🛑 校验失败：${result.error}`);
      return 2;
    }

    console.log('');
    console.log(renderSummary({ results: result.results }));

    const nonCompliant = result.results.some((r) => r.status === 'missing' || r.status === 'mismatch');
    console.log('');
    if (nonCompliant) {
      console.error('❌ 生成的配置无法达到策略要求 —— 生成器可能存在缺陷');
      return 1;
    }
    console.log('✅ 生成的配置经本地实测可完全满足策略（配置语法与取值均正确）');
    return 0;
  } finally {
    await sim.close();
  }
}

/* ============================== main ============================== */

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h' || argv[0] === 'help') {
    console.log(HELP);
    return 0;
  }

  const command = argv[0];
  const args = parseArgs(argv.slice(1));

  switch (command) {
    case 'generate':
      return cmdGenerate(args);
    case 'import':
      return cmdImport(args);
    case 'verify':
      return cmdVerify(args);
    case 'advise':
      return cmdAdvise(args);
    case 'simulate':
      return cmdSimulate(args);
    default:
      console.error(`未知子命令：${command}\n`);
      console.log(HELP);
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    if (err instanceof PolicyError) {
      console.error(`\n🛑 策略校验失败：\n${err.message}`);
      console.error('   —— 策略文件会被渲染进各平台配置语法，因此必须通过全部基线检查。');
    } else {
      console.error(`\n🛑 运行失败：${err.message}`);
    }
    process.exit(2);
  });
