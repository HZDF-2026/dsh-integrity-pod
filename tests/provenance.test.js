import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { makeCtx } from './harness.js'
import { apply, name as pluginName } from '../plugins/dsh-integrity-provenance/index.js'

const work = await mkdtemp(path.join(tmpdir(), 'provenance-'))
const store = path.join(work, 'provenance.jsonl')
const artifact = path.join(work, 'art.txt')
const input = path.join(work, 'input.txt')
const harness = makeCtx()
apply(harness.ctx)

const sha256 = (text) => createHash('sha256').update(text).digest('hex')

test.after(() => rm(work, { recursive: true, force: true }))

await writeFile(input, 'input-v1')
await writeFile(artifact, 'artifact-v1')

test('A1: two tools registered', () => {
  assert.equal(pluginName, 'integrity-provenance')
  assert.deepEqual(
    harness.registeredTools.map((tool) => tool.name).sort(),
    ['provenance_record', 'provenance_verify'],
  )
})

test('A5: record binds artifact, inputs and pipeline', async () => {
  const result = await harness.call('provenance_record', {
    artifact,
    inputs: JSON.stringify([input]),
    pipeline: 'cp input.txt art.txt (conceptual)',
    store,
  })
  assert.equal(result.id, 'PV-001')
  assert.equal(result.artifactSha256, sha256('artifact-v1'))
  assert.equal(result.inputCount, 1)
  assert.match(result.hash, /^[0-9a-f]{64}$/)
})

test('A5: untouched artifact verifies as intact', async () => {
  const result = await harness.call('provenance_verify', { id: 'PV-001', store })
  assert.equal(result.verdict, 'intact')
  assert.equal(result.chainVerified, true)
  assert.equal(result.currentSha256, sha256('artifact-v1'))
})

test('A5: modified artifact verifies as drifted', async () => {
  await writeFile(artifact, 'artifact-v2')
  const result = await harness.call('provenance_verify', { id: 'PV-001', store })
  assert.equal(result.verdict, 'drifted')
  assert.equal(result.currentSha256, sha256('artifact-v2'))
})

test('A5: rerun regenerating identical content verifies as reproducible', async () => {
  const forwardPath = artifact.split(path.sep).join('/')
  const result = await harness.call('provenance_verify', {
    id: 'PV-001',
    rerun: `node -e "require('fs').writeFileSync('${forwardPath}', 'artifact-v1')"`,
    cwd: work,
    timeoutMs: 30000,
    store,
  })
  assert.equal(result.verdict, 'reproducible')
  assert.equal(result.rerun.exitCode, 0)
  assert.equal(result.currentSha256, sha256('artifact-v1'))
})

test('A5: rerun generating different content verifies as divergent', async () => {
  const forwardPath = artifact.split(path.sep).join('/')
  const result = await harness.call('provenance_verify', {
    id: 'PV-001',
    rerun: `node -e "require('fs').writeFileSync('${forwardPath}', 'artifact-v3')"`,
    cwd: work,
    timeoutMs: 30000,
    store,
  })
  assert.equal(result.verdict, 'divergent')
})

test('A5: store tampering shows up as chainVerified false', async () => {
  const lines = (await readFile(store, 'utf8')).trim().split('\n')
  const record = JSON.parse(lines[0])
  record.artifactSha256 = '0'.repeat(64)
  lines[0] = JSON.stringify(record)
  await writeFile(store, lines.join('\n') + '\n', 'utf8')
  const result = await harness.call('provenance_verify', { id: 'PV-001', store })
  assert.equal(result.chainVerified, false)
})

test('rejects missing artifact, missing input, unknown id', async () => {
  await assert.rejects(
    () => harness.call('provenance_record', { artifact: path.join(work, 'nope.txt'), pipeline: 'x', store }),
    /artifact not found/,
  )
  await assert.rejects(
    () => harness.call('provenance_record', { artifact, inputs: path.join(work, 'nope-input.txt'), pipeline: 'x', store }),
    /input not found/,
  )
  await assert.rejects(
    () => harness.call('provenance_verify', { id: 'PV-999', store }),
    /not found/,
  )
})
