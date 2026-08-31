import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'integrity-adjudicate'
export const inject = ['tools']

const DEFAULT_STORE = '.integrity/prereg.jsonl'

const sha256 = (text) => createHash('sha256').update(text).digest('hex')

// Field order MUST stay identical to dsh-integrity-prereg so a chain verified
// here matches the chain written there.
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

function verifyChain(records) {
  for (let i = 0; i < records.length; i++) {
    const record = records[i]
    const expectedPrev = i === 0 ? null : records[i - 1].hash
    if (record.prevHash !== expectedPrev || record.hash !== chainHash(record)) return false
  }
  return true
}

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'adjudicate',
    description: 'Adjudicate a measured numeric result against a decision boundary. Preferred input is a preregId from prereg_register, so the boundary is provably pre-registered; passing a raw boundary is allowed but the result is flagged "post-hoc". Verdicts: supported / falsified / inconclusive (inside the tolerance band).',
    parameters: {
      measured: { type: 'number', required: true, description: 'The measured value to adjudicate.' },
      preregId: { type: 'string', description: 'Pre-registration record id (e.g. "PR-001") that owns the boundary.' },
      boundary: { type: 'number', description: 'Explicit decision boundary. Used only when preregId is absent; the result will be flagged "post-hoc".' },
      direction: { type: 'string', description: '"above" (supported when measured > boundary) or "below". Overrides the registered direction.' },
      tolerance: { type: 'number', description: 'Absolute tolerance band around the boundary; measurements inside are "inconclusive". Overrides the registered tolerance.' },
      claim: { type: 'string', description: 'Optional one-line description of the claim being adjudicated.' },
      store: { type: 'string', description: 'Pre-registration store path. Default ".integrity/prereg.jsonl" relative to cwd.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      if (!Number.isFinite(args.measured)) throw new Error('measured must be a finite number.')
      let boundary
      let direction
      let tolerance
      let boundaryProvenance
      let preregId = null
      let preregChainVerified = null

      if (args.preregId != null && args.preregId !== '') {
        const storePath = path.resolve(args.store ?? DEFAULT_STORE)
        const records = await loadStore(storePath)
        const record = records.find((entry) => entry.id === args.preregId)
        if (!record) throw new Error(`prereg record not found: ${args.preregId} (${storePath})`)
        if (record.boundary == null) {
          throw new Error(`prereg record ${args.preregId} carries no numeric boundary; register one before adjudicating.`)
        }
        preregId = record.id
        preregChainVerified = verifyChain(records)
        boundary = record.boundary
        direction = args.direction ?? record.direction ?? 'above'
        tolerance = args.tolerance ?? record.tolerance ?? 0
        boundaryProvenance = 'preregistered'
      } else {
        if (args.boundary == null || !Number.isFinite(args.boundary)) {
          throw new Error('Provide preregId (preferred) or an explicit numeric boundary.')
        }
        boundary = args.boundary
        direction = args.direction ?? 'above'
        tolerance = args.tolerance ?? 0
        boundaryProvenance = 'post-hoc'
      }

      if (direction !== 'above' && direction !== 'below') throw new Error('direction must be "above" or "below".')
      if (!(tolerance >= 0)) throw new Error('tolerance must be a non-negative number.')

      const margin = args.measured - boundary
      const distance = Math.abs(margin)
      let verdict
      if (distance <= tolerance) {
        verdict = 'inconclusive'
      } else if (direction === 'above') {
        verdict = margin > 0 ? 'supported' : 'falsified'
      } else {
        verdict = margin < 0 ? 'supported' : 'falsified'
      }

      return JSON.stringify({
        verdict,
        claim: (args.claim ?? '').trim() || null,
        measured: args.measured,
        boundary,
        direction,
        tolerance,
        margin,
        boundaryProvenance,
        preregId,
        preregChainVerified,
      })
    },
  }))
}
