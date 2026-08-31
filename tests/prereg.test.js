import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { makeCtx } from './harness.js'
import { apply, name as pluginName, inject } from '../plugins/dsh-integrity-prereg/index.js'

const work = await mkdtemp(path.join(tmpdir(), 'prereg-'))
const store = path.join(work, 'prereg.jsonl')
const harness = makeCtx()
apply(harness.ctx)

test.after(() => rm(work, { recursive: true, force: true }))

test('A1: plugin shape and three tools registered', () => {
  assert.equal(pluginName, 'integrity-prereg')
  assert.deepEqual(inject, ['tools'])
  assert.deepEqual(
    harness.registeredTools.map((tool) => tool.name).sort(),
    ['prereg_list', 'prereg_register', 'prereg_verify'],
  )
})

test('prereg_register appends and returns id/hash', async () => {
  const result = await harness.call('prereg_register', {
    claim: 'Method A beats the baseline',
    boundary: 2.0,
    direction: 'above',
    tolerance: 0.2,
    decisionRules: 'single boundary, no post-hoc moves',
    store,
  })
  assert.equal(result.id, 'PR-001')
  assert.match(result.hash, /^[0-9a-f]{64}$/)
  assert.equal(result.recordCount, 1)
  const lines = (await readFile(store, 'utf8')).trim().split('\n')
  assert.equal(lines.length, 1)
  const record = JSON.parse(lines[0])
  assert.equal(record.id, 'PR-001')
  assert.equal(record.prevHash, null)
})

test('A2: chain verifies after three records', async () => {
  await harness.call('prereg_register', { claim: 'Claim two', boundary: 1.0, store })
  await harness.call('prereg_register', { claim: 'Claim three', boundary: 0.5, direction: 'below', store })
  const result = await harness.call('prereg_verify', { store })
  assert.equal(result.verified, true)
  assert.equal(result.recordCount, 3)
  assert.equal(result.firstMismatch, null)
})

test('A2: tampering record 2 is detected with firstMismatch', async () => {
  const lines = (await readFile(store, 'utf8')).trim().split('\n')
  const record = JSON.parse(lines[1])
  record.claim = 'quietly rewritten claim'
  lines[1] = JSON.stringify(record)
  await writeFile(store, lines.join('\n') + '\n', 'utf8')
  const result = await harness.call('prereg_verify', { store })
  assert.equal(result.verified, false)
  assert.equal(result.recordCount, 3)
  assert.equal(result.firstMismatch.id, 'PR-002')
  assert.equal(result.firstMismatch.reason, 'hash mismatch')
})

test('prereg_list summarizes records', async () => {
  const result = await harness.call('prereg_list', { store })
  assert.equal(result.recordCount, 3)
  assert.equal(result.records[0].id, 'PR-001')
  assert.match(result.records[2].hash, /^[0-9a-f]{12}$/)
})

test('rejects empty claim and invalid direction', async () => {
  await assert.rejects(() => harness.call('prereg_register', { claim: '   ', store }), /non-empty/)
  await assert.rejects(
    () => harness.call('prereg_register', { claim: 'x', direction: 'sideways', store }),
    /direction must be/,
  )
})
