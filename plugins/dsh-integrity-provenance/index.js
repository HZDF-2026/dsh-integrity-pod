import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFile, mkdir, readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'integrity-provenance'
export const inject = ['tools']

const DEFAULT_STORE = '.integrity/provenance.jsonl'
const DEFAULT_TIMEOUT_MS = 120000
const OUTPUT_CAP_BYTES = 10 * 1024 * 1024

const sha256 = (data) => createHash('sha256').update(data).digest('hex')

function sanitizedEnv(base) {
  const env = { ...base }
  for (const key of Object.keys(env)) {
    if (/^(TZ|LANG|LC_[A-Z_]+|TERM|COLUMNS|LINES|SESSIONNAME|SESSION)$/.test(key)) delete env[key]
  }
  return Object.assign(env, { TZ: 'UTC', LC_ALL: 'C', SOURCE_DATE_EPOCH: '946684800', PYTHONHASHSEED: '0' })
}

function runCommand(command, { cwd, timeoutMs, signal }) {
  return new Promise((resolve) => {
    const chunks = []
    let bytes = 0
    let settled = false
    const child = spawn(command, { cwd, shell: true, env: sanitizedEnv(process.env), windowsHide: true })
    const finish = (exitCode) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve({ exitCode })
    }
    const timer = setTimeout(() => child.kill(), timeoutMs)
    const onAbort = () => child.kill()
    if (signal) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }
    child.stdout.on('data', (chunk) => {
      if (bytes < OUTPUT_CAP_BYTES) {
        chunks.push(chunk)
        bytes += chunk.length
      }
    })
    child.stderr.on('data', (chunk) => {})
    child.on('error', () => finish(126))
    child.on('close', (code) => finish(code))
  })
}

function runGit(args, cwd) {
  return new Promise((resolve) => {
    const child = spawn('git', args, { cwd, shell: true, windowsHide: true })
    let out = ''
    child.stdout.on('data', (chunk) => { out += chunk })
    child.on('error', () => resolve(null))
    child.on('close', (code) => resolve(code === 0 ? out.trim() : null))
  })
}

const sha256File = async (filePath) => createHash('sha256').update(await readFile(filePath)).digest('hex')

function payloadOf(record) {
  return {
    id: record.id,
    recordedAt: record.recordedAt,
    artifact: record.artifact,
    artifactSha256: record.artifactSha256,
    inputs: record.inputs,
    pipeline: record.pipeline,
    gitCommit: record.gitCommit,
    repoDirty: record.repoDirty,
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
      throw new Error(`provenance store corrupted: line ${i + 1} is not JSON (${storePath})`)
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

function parseInputs(raw) {
  if (raw == null || raw === '') return []
  const trimmed = String(raw).trim()
  let list
  if (trimmed.startsWith('[')) {
    try {
      list = JSON.parse(trimmed)
    } catch {
      throw new Error('inputs must be a JSON array string or a comma/newline separated path list.')
    }
    if (!Array.isArray(list)) throw new Error('inputs JSON must be an array of path strings.')
  } else {
    list = trimmed.split(/[\n,]/)
  }
  return list.map((entry) => String(entry).trim()).filter((entry) => entry !== '')
}

async function appendRecord(storePath, record) {
  await mkdir(path.dirname(storePath), { recursive: true })
  await appendFile(storePath, JSON.stringify(record) + '\n', 'utf8')
}

async function currentSha(filePath) {
  try {
    await stat(filePath)
  } catch (error) {
    if (error?.code === 'ENOENT') return null
    throw error
  }
  return sha256File(filePath)
}

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'provenance_record',
    description: 'Record provenance for an artifact: SHA256 of the artifact and every input, the pipeline that produces it, and the git commit of the cwd. Append-only and hash-chained. Record BEFORE the artifact can drift.',
    parameters: {
      artifact: { type: 'string', required: true, description: 'Path of the artifact file produced by the pipeline.' },
      inputs: { type: 'string', description: 'Input file paths: JSON array string or comma/newline separated list.' },
      pipeline: { type: 'string', required: true, description: 'Command or precise description of the pipeline that turns inputs into the artifact.' },
      store: { type: 'string', description: 'Store file path. Default ".integrity/provenance.jsonl" relative to cwd.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const artifactPath = path.resolve(args.artifact ?? '')
      if (!args.artifact?.trim()) throw new Error('artifact must be a non-empty path.')
      const artifactSha256 = await currentSha(artifactPath)
      if (artifactSha256 == null) throw new Error(`artifact not found: ${artifactPath}`)

      const inputs = []
      for (const inputPath of parseInputs(args.inputs)) {
        const resolved = path.resolve(inputPath)
        const hash = await currentSha(resolved)
        if (hash == null) throw new Error(`input not found: ${resolved}`)
        inputs.push({ path: resolved, sha256: hash })
      }

      const cwd = process.cwd()
      const gitCommit = await runGit(['rev-parse', 'HEAD'], cwd)
      const status = await runGit(['status', '--porcelain'], cwd)
      const repoDirty = status == null ? null : status !== ''

      const storePath = path.resolve(args.store ?? DEFAULT_STORE)
      const records = await loadStore(storePath)
      const record = {
        id: `PV-${String(records.length + 1).padStart(3, '0')}`,
        recordedAt: new Date().toISOString(),
        artifact: artifactPath,
        artifactSha256,
        inputs,
        pipeline: (args.pipeline ?? '').trim(),
        gitCommit,
        repoDirty,
        prevHash: records.length ? records[records.length - 1].hash : null,
      }
      record.hash = chainHash(record)
      await appendRecord(storePath, record)

      return JSON.stringify({
        id: record.id,
        artifact: record.artifact,
        artifactSha256,
        inputCount: inputs.length,
        gitCommit,
        repoDirty,
        hash: record.hash,
        store: storePath,
      })
    },
  }))

  ctx.tools.register(defineTool({
    name: 'provenance_verify',
    description: 'Verify a provenance record: re-hash the artifact now ("intact"/"drifted"/"missing"), or re-run the regeneration pipeline and compare the regenerated hash to the recorded one ("reproducible"/"divergent"). Also reports store chain integrity.',
    parameters: {
      id: { type: 'string', required: true, description: 'Provenance record id, e.g. "PV-001".' },
      rerun: { type: 'string', description: 'Optional regeneration command; when provided it runs first and the regenerated artifact is compared to the recorded hash.' },
      cwd: { type: 'string', description: 'Working directory for the rerun command. Default: process cwd.' },
      timeoutMs: { type: 'number', description: 'Timeout for the rerun command in milliseconds. Default 120000.' },
      store: { type: 'string', description: 'Store file path. Default ".integrity/provenance.jsonl" relative to cwd.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      if (!args.id?.trim()) throw new Error('id must be a non-empty string.')
      const storePath = path.resolve(args.store ?? DEFAULT_STORE)
      const records = await loadStore(storePath)
      const record = records.find((entry) => entry.id === args.id.trim())
      if (!record) throw new Error(`provenance record not found: ${args.id} (${storePath})`)
      const chainVerified = verifyChain(records)

      let verdict
      if (args.rerun != null && args.rerun.trim() !== '') {
        const timeoutMs = args.timeoutMs ?? DEFAULT_TIMEOUT_MS
        if (!(timeoutMs > 0)) throw new Error('timeoutMs must be a positive number.')
        const run = await runCommand(args.rerun, { cwd: path.resolve(args.cwd ?? process.cwd()), timeoutMs, signal: exec?.signal })
        const regenerated = await currentSha(record.artifact)
        if (regenerated == null) verdict = 'missing'
        else if (regenerated === record.artifactSha256) verdict = 'reproducible'
        else verdict = 'divergent'
        return JSON.stringify({
          verdict,
          id: record.id,
          artifact: record.artifact,
          recordedSha256: record.artifactSha256,
          currentSha256: regenerated,
          rerun: { command: args.rerun, exitCode: run.exitCode },
          chainVerified,
          store: storePath,
        })
      }

      const current = await currentSha(record.artifact)
      if (current == null) verdict = 'missing'
      else if (current === record.artifactSha256) verdict = 'intact'
      else verdict = 'drifted'
      return JSON.stringify({
        verdict,
        id: record.id,
        artifact: record.artifact,
        recordedSha256: record.artifactSha256,
        currentSha256: current,
        rerun: null,
        chainVerified,
        store: storePath,
      })
    },
  }))
}
