#!/usr/bin/env node
/**
 * 零依赖自检
 *
 * "零依赖"是本项目的核心承诺（供应链攻击面为零、CI 无需 npm install），
 * 因此由 CI 强制校验，而不是只在 README 里写一句。
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_DIRS = ['src', 'tests', 'scripts'];
const problems = [];

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
  const names = Object.keys(pkg[field] || {});
  if (names.length) problems.push(`package.json 的 ${field} 存在依赖：${names.join(', ')}`);
}

function walk(dir) {
  const abs = join(ROOT, dir);
  if (!existsSync(abs)) return [];
  const out = [];
  for (const entry of readdirSync(abs)) {
    const full = join(abs, entry);
    if (statSync(full).isDirectory()) out.push(...walk(join(dir, entry)));
    else if (/\.(mjs|js)$/.test(entry)) out.push(full);
  }
  return out;
}

const IMPORT_RE = /(?:^|\n)\s*(?:import|export)[^\n]*?from\s+['"]([^'"]+)['"]/g;
let fileCount = 0;

for (const dir of SCAN_DIRS) {
  for (const file of walk(dir)) {
    fileCount++;
    const source = readFileSync(file, 'utf8');
    let match;
    while ((match = IMPORT_RE.exec(source)) !== null) {
      const spec = match[1];
      if (!spec.startsWith('.') && !spec.startsWith('/') && !spec.startsWith('node:')) {
        problems.push(`${relative(ROOT, file)} 引用了非内置模块：${spec}`);
      }
    }
  }
}

if (existsSync(join(ROOT, 'node_modules'))) {
  problems.push('存在 node_modules 目录 —— 零依赖项目不应有它');
}

console.log(`扫描 ${fileCount} 个源文件`);
if (problems.length === 0) {
  console.log('✅ 零依赖校验通过：无第三方依赖，全部使用 Node 内置模块');
  process.exit(0);
}

console.error('❌ 零依赖校验失败：');
for (const p of problems) console.error(`   - ${p}`);
process.exit(1);
