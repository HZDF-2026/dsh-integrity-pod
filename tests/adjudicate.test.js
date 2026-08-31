import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { makeCtx } from './harness.js'
import { apply as applyPrereg } from '../plugins/dsh-integrity-prereg/index.js'
import { apply as applyAdjudicate, name as pluginName } from '../plugins/dsh-integrity-adjudicate/index.js'

const work = await mkdtemp(path.join(tmpdir(), 'adjudicate-'))
const store = path.join(work, 'prereg.jsonl')
const prereg = makeCtx()
applyPrereg(prereg.ctx)
const harness = makeCtx()
applyAdjudicate(harness.ctx)

test.after(() => rm(work, { recursive: true, force: true }))

await prereg.call('prereg_register', {
  claim: 'Method A beats baseline by at least 2.0',
  boundary: 2.0,
  direction: 'above',
  tolerance: 0.2,
  store,
})
await prereg.call('prereg_register', {
  claim: 'Error rate drops below 0.5',
  boundary: 0.5,
  direction: 'below',
  tolerance: 0.1,
  store,
})

test('A1: adjudicate tool registered', () => {
  assert.equal(pluginName, 'integrity-adjudicate')
  assert.equal(harness.tool('adjudicate').name, 'adjudicate')
})

test('A4: preregistered boundary, beyond tolerance → supported', async () => {
  const result = await harness.call('adjudicate', { measured: 2.5, preregId: 'PR-001', store })
  assert.equal(result.verdict, 'supported')
  assert.equal(result.boundaryProvenance, 'preregistered')
  assert.equal(result.boundary, 2.0)
  assert.equal(result.tolerance, 0.2)
  assert.equal(result.margin, 0.5)
  assert.equal(result.preregChainVerified, true)
})

test('A4: inside tolerance band → inconclusive', async () => {
  const result = await harness.call('adjudicate', { measured: 2.1, preregId: 'PR-001', store })
  assert.equal(result.verdict, 'inconclusive')
})

test('A4: far on the wrong side → falsified', async () => {
  const result = await harness.call('adjudicate', { measured: 1.0, preregId: 'PR-001', store })
  assert.equal(result.verdict, 'falsified')
  assert.equal(result.margin, -1)
})

test('A4: direction "below" mirrors correctly', async () => {
  const supported = await harness.call('adjudicate', { measured: 0.3, preregId: 'PR-002', store })
  assert.equal(supported.verdict, 'supported')
  const falsified = await harness.call('adjudicate', { measured: 0.9, preregId: 'PR-002', store })
  assert.equal(falsified.verdict, 'falsified')
})

test('A4: explicit boundary is flagged post-hoc', async () => {
  const result = await harness.call('adjudicate', { measured: 3.0, boundary: 1.0, direction: 'above' })
  assert.equal(result.verdict, 'supported')
  assert.equal(result.boundaryProvenance, 'post-hoc')
  assert.equal(result.preregId, null)
  assert.equal(result.preregChainVerified, null)
})

test('A4: tampered prereg store → preregChainVerified false', async () => {
  const lines = (await readFile(store, 'utf8')).trim().split('\n')
  const record = JSON.parse(lines[0])
  record.boundary = 999
  lines[0] = JSON.stringify(record)
  await writeFile(store, lines.join('\n') + '\n', 'utf8')
  const result = await harness.call('adjudicate', { measured: 0.3, preregId: 'PR-002', store })
  assert.equal(result.verdict, 'supported')
  assert.equal(result.preregChainVerified, false)
})

test('rejects unknown preregId, missing boundary, bad direction', async () => {
  await assert.rejects(() => harness.call('adjudicate', { measured: 1, preregId: 'PR-999', store }), /not found/)
  await assert.rejects(() => harness.call('adjudicate', { measured: 1 }), /preregId .* boundary/)
  await assert.rejects(
    () => harness.call('adjudicate', { measured: 1, boundary: 1, direction: 'sideways' }),
    /direction must be/,
  )
})
