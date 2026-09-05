// diff_cpp.mjs — differential test: the C++17 port vs the Node plugin
// reference. Each scenario runs the same operation sequence through the Node
// plugins (twin temp dir A, process chdir'ed into it) and the C++ CLI (twin
// temp dir B, invoked with cwd set to it). Tool JSON output, error messages,
// exit codes and every produced file are normalized (timestamps, durations,
// hash-chain values, absolute paths) and compared byte-for-byte.
//
//   node tests/cpp/diff_cpp.mjs [scenario]      (build first: make -C cpp)
//
// Normalization deliberately collapses volatile channels — wall-clock stamps
// and hashes derived from them — because the golden table (test_golden.cpp)
// already proves those paths bit-exact under fixed inputs. What this test
// proves is behavioral parity on live stores: identical verdicts and errors,
// identical chain/audit file structure, identical divergence reporting.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { apply as applyPrereg } from '../../plugins/dsh-integrity-prereg/index.js';
import { apply as applyAdjudicate } from '../../plugins/dsh-integrity-adjudicate/index.js';
import { apply as applyBitwin } from '../../plugins/dsh-integrity-bitwin/index.js';
import { apply as applyGuardrail } from '../../plugins/dsh-integrity-guardrail/index.js';
import { apply as applyProvenance } from '../../plugins/dsh-integrity-provenance/index.js';

const root = fileURLToPath(new URL('../..', import.meta.url));
const cppBin = path.join(root, 'dist', 'cpp',
  process.platform === 'win32' ? 'dship-integrity.exe' : 'dship-integrity');

// ---------------------------------------------------------------- normalization

function normalize(text, dir) {
  let out = String(text);
  const fwd = dir.split(path.sep).join('/');
  out = out.split(dir.split(path.sep).join('\\\\')).join('<DIR>'); // JSON-escaped
  out = out.split(dir).join('<DIR>'); // raw absolute path
  out = out.split(fwd).join('<DIR>'); // forward-slash variant
  out = out.replace(/\\/g, '/');
  out = out.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/g, '<TS>');
  out = out.replace(/"durationMs":\d+/g, '"durationMs":<MS>');
  // Quoted hex hashes: 64-char record/chain hashes, 16-char bitwin prefixes,
  // 12-char list/status prefixes. Quote anchoring keeps the lengths exclusive.
  out = out.replace(/"([0-9a-f]{64})"/g, '"<HASH64>"');
  out = out.replace(/"([0-9a-f]{16})"/g, '"<HASH16>"');
  out = out.replace(/"([0-9a-f]{12})"/g, '"<HASH12>"');
  return out;
}

// ------------------------------------------------------------- node-side harness

function makeCtx() {
  const tools = new Map();
  const handlers = {};
  return {
    tools: { register: (tool) => tools.set(tool.name, tool) },
    on: (event, handler) => { (handlers[event] ??= []).push(handler); },
    _tools: tools,
    _handlers: handlers,
  };
}

async function runNodeTool(ctx, name, args) {
  try {
    return { ok: true, out: await ctx._tools.get(name).execute(args) };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

// The guardrail plugin lives at the hook layer, not the tool layer. Every step
// gets a fresh harness (config is fixed at apply() time); the audit log file
// persists across steps in the scenario dir and each apply() re-reads it
// before appending — the same disk-backed semantics as separate CLI calls.
// Status must run in the ctx of the immediately preceding check: a fresh ctx
// does not re-read the audit file until it appends once, so every status
// step below directly follows an appending check step.
async function runNodeGuardrail(op, spec, state) {
  if (op === 'status') {
    if (!state.ctx) return { ok: false, error: 'status must follow a check step' };
    return { ok: true, out: await state.ctx._tools.get('guardrail_status').execute({}) };
  }
  const ctx = makeCtx();
  try {
    applyGuardrail(ctx, spec.config ?? {});
  } catch (error) {
    return { ok: false, error: error.message };
  }
  state.ctx = ctx;
  if (op === 'check') {
    const handler = ctx._handlers['tools/pre-execute'][0];
    const result = await handler({ name: spec.tool, arguments: spec.args, callId: spec.callId },
      () => ({ kind: 'allow' }));
    return { ok: true, out: JSON.stringify(result ?? { kind: 'allow' }) };
  }
  // log-result: the Node hook returns nothing (the append is fire-and-forget,
  // hence the settle sleep); {"appended":bool} is the CLI's convention, false
  // exactly when auditLog is disabled.
  const handler = ctx._handlers['tools/result'][0];
  handler({ name: spec.tool, isError: Boolean(spec.isError), callId: spec.callId });
  await new Promise((resolve) => setTimeout(resolve, 80));
  return { ok: true, out: JSON.stringify({ appended: (spec.config ?? {}).auditLog !== false }) };
}

// --------------------------------------------------------------- cpp-side calls

function runCpp(argv, dir) {
  const r = spawnSync(cppBin, argv, { cwd: dir, encoding: 'utf8' });
  if (r.status === 0) return { ok: true, out: r.stdout.trim() };
  return { ok: false, error: (r.stderr || '').trim().replace(/^error: /, '') };
}

const CLI_MAP = {
  prereg_register: { argv: ['prereg', 'register'],
    opts: { claim: 'claim', boundary: 'boundary', direction: 'direction', tolerance: 'tolerance', decisionRules: 'decision-rules', store: 'store' } },
  prereg_list: { argv: ['prereg', 'list'], opts: { store: 'store' } },
  prereg_verify: { argv: ['prereg', 'verify'], opts: { store: 'store' } },
  adjudicate: { argv: ['adjudicate'],
    opts: { measured: 'measured', preregId: 'prereg-id', boundary: 'boundary', direction: 'direction', tolerance: 'tolerance', claim: 'claim', store: 'store' } },
  provenance_record: { argv: ['provenance', 'record'],
    opts: { artifact: 'artifact', inputs: 'inputs', pipeline: 'pipeline', store: 'store' } },
  provenance_verify: { argv: ['provenance', 'verify'],
    opts: { id: 'id', rerun: 'rerun', cwd: 'cwd', timeoutMs: 'timeout-ms', store: 'store' } },
  bitwin_run: { argv: ['bitwin', 'run'],
    opts: { command: 'command', cwd: 'cwd', timeoutMs: 'timeout-ms' } },
};

function cppArgv(tool, args) {
  const spec = CLI_MAP[tool];
  const argv = [...spec.argv];
  for (const [key, flag] of Object.entries(spec.opts)) {
    if (args[key] !== undefined && args[key] !== null) argv.push(`--${flag}`, String(args[key]));
  }
  return argv;
}

function cppGuardrailArgv(op, spec) {
  const cfg = spec.config ?? {};
  const argv = ['guardrail', op];
  if (op === 'check') {
    argv.push('--tool', spec.tool);
    if (spec.callId !== undefined) argv.push('--call-id', spec.callId);
    if (spec.args !== undefined) argv.push('--args-json', JSON.stringify(spec.args));
  } else if (op === 'log-result') {
    argv.push('--tool', spec.tool);
    if (spec.isError) argv.push('--is-error');
    if (spec.callId !== undefined) argv.push('--call-id', spec.callId);
  }
  if (cfg.mode !== undefined) argv.push('--mode', cfg.mode);
  for (const p of cfg.extraDenyPatterns ?? []) argv.push('--extra-deny', p);
  for (const p of cfg.allowPatterns ?? []) argv.push('--allow', p);
  if (cfg.integrityStoreDir !== undefined) argv.push('--integrity-store-dir', cfg.integrityStoreDir);
  if (cfg.protectIntegrityStores === false) argv.push('--no-protect-integrity-stores');
  if (cfg.auditLog === false) argv.push('--no-audit-log');
  if (cfg.auditPath !== undefined) argv.push('--audit-path', cfg.auditPath);
  return argv;
}

// ------------------------------------------------------------------ file trees

function collectFiles(dir) {
  const out = new Map();
  const walk = (rel) => {
    for (const entry of readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(relPath);
      else out.set(relPath, readFileSync(path.join(dir, relPath), 'utf8'));
    }
  };
  walk('.');
  return out;
}

// ------------------------------------------------------------------- scenarios

const MODEL_BYTES = 'deterministic artifact bytes\n';
const CSV_BYTES = 'a,b\n1,2\n';
const MAKE_ARTIFACT = "require('fs').writeFileSync('model.bin', 'deterministic artifact bytes\\n')\n";
const STABLE_WRITER = "require('fs').writeFileSync('stable.txt', 'stable content\\n')\n";
// Appends, so run 1 and run 2 of a bitwin double-run are guaranteed to differ.
const APPEND_WRITER = "require('fs').appendFileSync('out.txt', 'line\\n')\n";

const SCENARIOS = [
  {
    name: 'prereg-adjudicate',
    setup() {},
    steps: [
      { tool: 'prereg_register', args: { claim: 'accuracy above 0.75 on held-out set', boundary: 0.75, direction: 'above', tolerance: 0.05, decisionRules: 'exclude runs with errors' } },
      { tool: 'prereg_register', args: { claim: 'p99 latency below 120 ms', boundary: 120, direction: 'below' } },
      { tool: 'prereg_register', args: { claim: '   ' } },
      { tool: 'prereg_register', args: { claim: 'x', direction: 'sideways' } },
      { tool: 'prereg_list', args: {} },
      { tool: 'adjudicate', args: { measured: 0.9, preregId: 'PR-001' } },
      { tool: 'adjudicate', args: { measured: 0.76, preregId: 'PR-001' } },
      { tool: 'adjudicate', args: { measured: 0.72, preregId: 'PR-001' } },
      { tool: 'adjudicate', args: { measured: 90, preregId: 'PR-002' } },
      { tool: 'adjudicate', args: { measured: 130, preregId: 'PR-002' } },
      { tool: 'adjudicate', args: { measured: 125, preregId: 'PR-002', tolerance: 25 } },
      { tool: 'adjudicate', args: { measured: 6, boundary: 5 } },
      { tool: 'adjudicate', args: { measured: 5, preregId: 'PR-999' } },
      { tool: 'prereg_verify', args: {} },
      { tamper: '.integrity/prereg.jsonl' },
      { tool: 'prereg_verify', args: {} },
      { tool: 'adjudicate', args: { measured: 0.9, preregId: 'PR-001' } },
      { tool: 'prereg_list', args: {} },
    ],
  },
  {
    name: 'provenance',
    setup(dir) {
      writeFileSync(path.join(dir, 'model.bin'), MODEL_BYTES);
      writeFileSync(path.join(dir, 'input.csv'), CSV_BYTES);
      writeFileSync(path.join(dir, 'make-artifact.js'), MAKE_ARTIFACT);
    },
    steps: [
      { tool: 'provenance_record', args: { artifact: 'model.bin', inputs: 'input.csv', pipeline: 'node make-artifact.js' } },
      { tool: 'provenance_record', args: { artifact: 'missing.bin', pipeline: 'x' } },
      { tool: 'provenance_record', args: { artifact: 'model.bin', inputs: 'gone.txt', pipeline: 'p' } },
      { tool: 'provenance_record', args: { artifact: 'model.bin', inputs: '[', pipeline: 'p' } },
      { tool: 'provenance_record', args: { artifact: 'model.bin', inputs: '["input.csv","model.bin"]', pipeline: 'second pipeline' } },
      { tool: 'provenance_verify', args: { id: 'PV-001' } },
      { tool: 'provenance_verify', args: { id: 'PV-001', rerun: 'node make-artifact.js' } },
      { tool: 'provenance_verify', args: { id: 'PV-999' } },
      { tool: 'provenance_record', args: { artifact: 'model.bin', pipeline: 'p2', store: 'custom-store.jsonl' } },
      { tool: 'provenance_verify', args: { id: 'PV-999', store: 'custom-store.jsonl' } },
      { drift: 'model.bin' },
      { tool: 'provenance_verify', args: { id: 'PV-001' } },
      { tool: 'provenance_verify', args: { id: 'PV-002' } },
    ],
  },
  {
    name: 'bitwin',
    setup(dir) {
      writeFileSync(path.join(dir, 'write-stable.js'), STABLE_WRITER);
      writeFileSync(path.join(dir, 'write-append.js'), APPEND_WRITER);
    },
    steps: [
      { tool: 'bitwin_run', args: { command: 'echo hello' } },
      { tool: 'bitwin_run', args: { command: 'node write-stable.js' } },
      { tool: 'bitwin_run', args: { command: 'node write-append.js' } },
      { tool: 'bitwin_run', args: { command: 'node -e "process.exit(3)"' } },
    ],
  },
  {
    name: 'guardrail',
    setup() {},
    steps: [
      { guardrail: ['check', { tool: 'bash', args: { command: 'echo ok' } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'rm -rf /' } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'rm -rf ./build' } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'sudo apt install x' } }] },
      { guardrail: ['check', { tool: 'read_file', args: { path: '.env' } }] },
      { guardrail: ['check', { tool: 'read_file', args: { path: 'config.yaml' } }] },
      { guardrail: ['check', { tool: 'bash', args: 'sudo rm x' }] },
      { guardrail: ['check', { tool: 'bash', args: ['rm', '-rf', '/'] }] },
      { guardrail: ['check', { tool: 'bash', args: null }] },
      { guardrail: ['log-result', { tool: 'bash' }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'shutdown /r /t 0' } }] },
      { guardrail: ['status', {}] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'sudo apt install x' }, config: { mode: 'audit' } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'sudo apt install x' }, config: { allowPatterns: ['apt install'] } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'run forbidden-ritual' }, config: { extraDenyPatterns: ['forbidden-ritual'] } }] },
      { guardrail: ['check', { tool: 'edit', args: { path: '.integrity/prereg.jsonl' } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'cat .integrity/prereg.jsonl' } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'rm -rf custom-store/x' }, config: { integrityStoreDir: 'custom-store' } }] },
      { guardrail: ['check', { tool: 'edit', args: { path: '.integrity/prereg.jsonl' }, config: { protectIntegrityStores: false } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'rm -rf /' }, config: { extraDenyPatterns: ['('] } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'rm -rf /' }, config: { mode: 'weird' } }] },
      { guardrail: ['log-result', { tool: 'bash', isError: true, config: { auditLog: false } }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'sudo x' }, callId: 'c-42' }] },
      { guardrail: ['check', { tool: 'bash', args: { command: 'mkfs.ext4 /dev/sda' } }] },
      { guardrail: ['status', {}] },
    ],
  },
];

// ---------------------------------------------------------------------- runner

let failures = 0;

function report(scenario, step, side, detail) {
  failures++;
  console.error(`FAIL [${scenario}] step ${step} (${side}): ${detail}`);
}

function compareResult(scenario, index, nodeSide, cppSide, dirN, dirC) {
  const n = nodeSide.ok
    ? { ok: true, out: normalize(nodeSide.out, dirN) }
    : { ok: false, error: normalize(nodeSide.error ?? '', dirN) };
  const c = cppSide.ok
    ? { ok: true, out: normalize(cppSide.out, dirC) }
    : { ok: false, error: normalize(cppSide.error ?? '', dirC) };
  if (n.ok !== c.ok) {
    report(scenario, index, 'status', `node ok=${n.ok} cpp ok=${c.ok}\n  node: ${JSON.stringify(n)}\n  cpp:  ${JSON.stringify(c)}`);
    return;
  }
  const a = n.ok ? n.out : n.error;
  const b = c.ok ? c.out : c.error;
  if (a !== b) {
    report(scenario, index, 'output', `mismatch\n  node: ${JSON.stringify(a)}\n  cpp:  ${JSON.stringify(b)}`);
  }
}

async function runScenario(scenario) {
  const base = mkdtempSync(path.join(tmpdir(), `dship-diff-${scenario.name}-`));
  const dirN = path.join(base, 'node');
  const dirC = path.join(base, 'cpp');
  mkdirSync(dirN); mkdirSync(dirC);
  scenario.setup(dirN); scenario.setup(dirC);

  const prevCwd = process.cwd();
  process.chdir(dirN);
  const ctx = makeCtx();
  applyPrereg(ctx); applyAdjudicate(ctx); applyProvenance(ctx); applyBitwin(ctx);
  const guard = { ctx: null };

  try {
    let index = 0;
    for (const step of scenario.steps) {
      index++;
      if (step.tamper) {
        // Rewrite the first store record's claim on both sides, keeping the
        // recorded hashes — the classic post-hoc edit the chain must catch.
        for (const dir of [dirN, dirC]) {
          const file = path.join(dir, ...step.tamper.split('/'));
          const lines = readFileSync(file, 'utf8').split(/\r?\n/).filter((l) => l.trim());
          const record = JSON.parse(lines[0]);
          record.claim = 'tampered after the fact';
          lines[0] = JSON.stringify(record);
          writeFileSync(file, lines.join('\n') + '\n');
        }
        continue;
      }
      if (step.drift) {
        for (const dir of [dirN, dirC]) writeFileSync(path.join(dir, step.drift), 'drifted content\n');
        continue;
      }
      if (step.guardrail) {
        const [op, spec] = step.guardrail;
        const nodeSide = await runNodeGuardrail(op, spec, guard);
        const cppSide = runCpp(cppGuardrailArgv(op, spec), dirC);
        compareResult(scenario.name, index, nodeSide, cppSide, dirN, dirC);
        continue;
      }
      const nodeSide = await runNodeTool(ctx, step.tool, step.args);
      const cppSide = runCpp(cppArgv(step.tool, step.args), dirC);
      compareResult(scenario.name, index, nodeSide, cppSide, dirN, dirC);
    }
  } finally {
    process.chdir(prevCwd);
  }

  const filesN = collectFiles(dirN);
  const filesC = collectFiles(dirC);
  const keysN = [...filesN.keys()].sort();
  const keysC = [...filesC.keys()].sort();
  if (keysN.join('|') !== keysC.join('|')) {
    report(scenario.name, 'files', 'listing', `node: [${keysN.join(', ')}]\n  cpp:  [${keysC.join(', ')}]`);
  } else {
    for (const key of keysN) {
      const a = normalize(filesN.get(key), dirN);
      const b = normalize(filesC.get(key), dirC);
      if (a !== b) {
        report(scenario.name, 'files', key,
          `mismatch\n  node: ${JSON.stringify(a.slice(0, 2000))}\n  cpp:  ${JSON.stringify(b.slice(0, 2000))}`);
      }
    }
  }
  rmSync(base, { recursive: true, force: true });
}

// ------------------------------------------------------------------------ main

try {
  readdirSync(path.dirname(cppBin));
} catch {
  console.error(`C++ binary not found at ${cppBin} — build it first: make -C cpp`);
  process.exit(1);
}

const only = process.argv[2];
for (const scenario of SCENARIOS) {
  if (only && scenario.name !== only) continue;
  const before = failures;
  await runScenario(scenario);
  console.log(`${failures === before ? 'ok  ' : 'FAIL'} ${scenario.name}`);
}

if (failures > 0) {
  console.error(`\n${failures} failure(s).`);
  process.exit(1);
}
console.log('\nall differential scenarios passed.');
