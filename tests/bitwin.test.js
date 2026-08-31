import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { makeCtx } from './harness.js'
import { apply, name as pluginName } from '../plugins/dsh-integrity-bitwin/index.js'

const work = await mkdtemp(path.join(tmpdir(), 'bitwin-'))
const harness = makeCtx()
apply(harness.ctx)

test.after(() => rm(work, { recursive: true, force: true }))

test('A1: bitwin_run registered', () => {
  assert.equal(pluginName, 'integrity-bitwin')
  assert.equal(harness.tool('bitwin_run').name, 'bitwin_run')
})

test('A3: deterministic command is bit_identical', async () => {
  const result = await harness.call('bitwin_run', {
    command: 'node -e "console.log(42)"',
    cwd: work,
    timeoutMs: 30000,
  })
  assert.equal(result.verdict, 'bit_identical')
  assert.equal(result.divergences.length, 0)
  assert.equal(result.runs[0].exitCode, 0)
  assert.equal(result.env.fixed.TZ, 'UTC')
})

test('A3: deterministic file-writing command is bit_identical', async () => {
  const result = await harness.call('bitwin_run', {
    command: 'node -e "require(\'fs\').writeFileSync(\'stable.txt\', \'v1\')"',
    cwd: work,
    timeoutMs: 30000,
  })
  assert.equal(result.verdict, 'bit_identical')
  assert.equal(result.checkedFiles, 1)
})

test('A3: random stdout diverges on stdout channel', async () => {
  const result = await harness.call('bitwin_run', {
    command: 'node -e "console.log(Math.random())"',
    cwd: work,
    timeoutMs: 30000,
  })
  assert.equal(result.verdict, 'divergent')
  assert.ok(result.divergences.some((entry) => entry.kind === 'stdout'))
  assert.ok(result.divergences.every((entry) => entry.kind !== 'file_hash'))
})

test('A3: random file content diverges on file_hash channel', async () => {
  const result = await harness.call('bitwin_run', {
    command: 'node -e "require(\'fs\').writeFileSync(\'out.txt\', String(Math.random()))"',
    cwd: work,
    timeoutMs: 30000,
  })
  assert.equal(result.verdict, 'divergent')
  const fileHash = result.divergences.find((entry) => entry.kind === 'file_hash')
  assert.equal(fileHash.path, 'out.txt')
  assert.match(fileHash.run1, /^[0-9a-f]{16}$/)
})

test('rejects empty command and invalid timeout', async () => {
  await assert.rejects(() => harness.call('bitwin_run', { command: '  ', cwd: work }), /non-empty/)
  await assert.rejects(
    () => harness.call('bitwin_run', { command: 'echo hi', cwd: work, timeoutMs: -1 }),
    /positive number/,
  )
})
