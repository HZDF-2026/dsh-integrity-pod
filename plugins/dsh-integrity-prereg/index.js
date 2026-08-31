import { createHash } from 'node:crypto'
import { appendFile, mkdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'integrity-prereg'
export const inject = ['tools']

const DEFAULT_STORE = '.integrity/prereg.jsonl'

const sha256 = (text) => createHash('sha256').update(text).digest('hex')

function payloadOf(record) {
  return {
    id: record.id,
    registeredAt: record.registeredAt,
    claim: record.claim,
    boundary: record.boundary,
    direction: record.direction,
    tolerance: record.tolerance,
    decisionRules: record.decisionRules,
    prevHash: record.prevHash,
  }
}

const chainHash = (record) => sha256(JSON.stringify(payloadOf(record)))

async function loadStore(storePath) {
  let text
  try {
    text = await readFile(storePath, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return []
    throw error
  }
  const records = []
  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].trim()) continue
    try {
      records.push(JSON.parse(lines[i]))
    } catch {
      throw new Error(`prereg store corrupted: line ${i + 1} is not JSON (${storePath})`)
    }
  }
  return records
}

async function appendRecord(storePath, record) {
  await mkdir(path.dirname(storePath), { recursive: true })
  await appendFile(storePath, JSON.stringify(record) + '\n', 'utf8')
}

function verifyChain(records) {
  for (let i = 0; i < records.length; i++) {
    const record = records[i]
    const expectedPrev = i === 0 ? null : records[i - 1].hash
    if (record.prevHash !== expectedPrev) {
      return { verified: false, recordCount: records.length, firstMismatch: { id: record.id, line: i + 1, reason: 'prevHash mismatch' } }
    }
    if (record.hash !== chainHash(record)) {
      return { verified: false, recordCount: records.length, firstMismatch: { id: record.id, line: i + 1, reason: 'hash mismatch' } }
    }
  }
  return { verified: true, recordCount: records.length, firstMismatch: null }
}

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'prereg_register',
    description: 'Pre-register a falsifiable claim with its numeric decision boundary BEFORE contacting the data. The record is append-only and hash-chained, so later edits are detectable. Use this before running experiments, evaluations or benchmarks.',
    parameters: {
      claim: { type: 'string', required: true, description: 'One-sentence falsifiable claim or hypothesis.' },
      boundary: { type: 'number', description: 'Numeric decision boundary that will adjudicate the claim.' },
      direction: { type: 'string', description: '"above" (supported when measured > boundary) or "below" (supported when measured < boundary). Default "above".' },
      tolerance: { type: 'number', description: 'Absolute tolerance band around the boundary; measurements inside the band are "inconclusive".' },
      decisionRules: { type: 'string', description: 'Free-form decision rules, thresholds, exclusions, analysis plan.' },
      store: { type: 'string', description: 'Store file path. Default ".integrity/prereg.jsonl" relative to cwd.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const claim = (args.claim ?? '').trim()
      if (!claim) throw new Error('claim must be a non-empty string.')
      const direction = args.direction ?? 'above'
      if (direction !== 'above' && direction !== 'below') throw new Error('direction must be "above" or "below".')
      if (args.tolerance != null && !(args.tolerance >= 0)) throw new Error('tolerance must be a non-negative number.')
      if (args.boundary != null && !Number.isFinite(args.boundary)) throw new Error('boundary must be a finite number.')
      const storePath = path.resolve(args.store ?? DEFAULT_STORE)
      const records = await loadStore(storePath)
      const record = {
        id: `PR-${String(records.length + 1).padStart(3, '0')}`,
        registeredAt: new Date().toISOString(),
        claim,
        boundary: args.boundary ?? null,
        direction,
        tolerance: args.tolerance ?? null,
        decisionRules: (args.decisionRules ?? '').trim() || null,
        prevHash: records.length ? records[records.length - 1].hash : null,
      }
      record.hash = chainHash(record)
      await appendRecord(storePath, record)
      return JSON.stringify({
        id: record.id,
        hash: record.hash,
        registeredAt: record.registeredAt,
        recordCount: records.length + 1,
        store: storePath,
      })
    },
  }))

  ctx.tools.register(defineTool({
    name: 'prereg_list',
    description: 'List pre-registered claims from the hash-chained store: id, claim, boundary, direction, tolerance, registration time.',
    parameters: {
      store: { type: 'string', description: 'Store file path. Default ".integrity/prereg.jsonl" relative to cwd.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const storePath = path.resolve(args.store ?? DEFAULT_STORE)
      const records = await loadStore(storePath)
      return JSON.stringify({
        store: storePath,
        recordCount: records.length,
        records: records.map((record) => ({
          id: record.id,
          claim: record.claim,
          boundary: record.boundary,
          direction: record.direction,
          tolerance: record.tolerance,
          registeredAt: record.registeredAt,
          hash: record.hash?.slice(0, 12),
        })),
      })
    },
  }))

  ctx.tools.register(defineTool({
    name: 'prereg_verify',
    description: 'Verify the integrity of the pre-registration store by recomputing the full hash chain. Reports "verified" plus the first mismatching record after any tampering.',
    parameters: {
      store: { type: 'string', description: 'Store file path. Default ".integrity/prereg.jsonl" relative to cwd.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const storePath = path.resolve(args.store ?? DEFAULT_STORE)
      const records = await loadStore(storePath)
      const result = verifyChain(records)
      return JSON.stringify({ store: storePath, ...result })
    },
  }))
}
