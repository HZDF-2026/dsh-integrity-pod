import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readdir, readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'integrity-bitwin'
export const inject = ['tools']

const DEFAULT_TIMEOUT_MS = 120000
const OUTPUT_CAP_BYTES = 10 * 1024 * 1024
const MAX_FILE_BYTES = 8 * 1024 * 1024
const MAX_FILE_COUNT = 2000
const SKIP_DIR_NAMES = new Set(['.git', 'node_modules', '.integrity'])

const STRIPPED_ENV_KEYS = /^(TZ|LANG|LC_[A-Z_]+|TERM|COLUMNS|LINES|SESSIONNAME|SESSION)$/
const FIXED_ENV = { TZ: 'UTC', LC_ALL: 'C', SOURCE_DATE_EPOCH: '946684800', PYTHONHASHSEED: '0' }

const sha256 = (data) => createHash('sha256').update(data).digest('hex')

function sanitizedEnv(base) {
  const env = { ...base }
  for (const key of Object.keys(env)) {
    if (STRIPPED_ENV_KEYS.test(key)) delete env[key]
  }
  return Object.assign(env, FIXED_ENV)
}

function runCommand(command, { cwd, timeoutMs, signal }) {
  return new Promise((resolve) => {
    const stdoutChunks = []
    const stderrChunks = []
    let stdoutBytes = 0
    let stderrBytes = 0
    let settled = false
    let timedOut = false
    let aborted = false
    const startedAt = Date.now()

    const child = spawn(command, { cwd, shell: true, env: sanitizedEnv(process.env), windowsHide: true })

    const finish = (exitCode) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', onAbort)
      const stdout = Buffer.concat(stdoutChunks)
      const stderr = Buffer.concat(stderrChunks)
      resolve({
        exitCode,
        timedOut,
        aborted,
        stdoutHash: sha256(stdout),
        stderrHash: sha256(stderr),
        stdoutBytes: stdout.length,
        stderrBytes: stderr.length,
        durationMs: Date.now() - startedAt,
      })
    }

    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, timeoutMs)

    const onAbort = () => {
      aborted = true
      child.kill()
    }
    if (signal) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }

    child.stdout.on('data', (chunk) => {
      if (stdoutBytes < OUTPUT_CAP_BYTES) {
        stdoutChunks.push(chunk)
        stdoutBytes += chunk.length
      }
    })
    child.stderr.on('data', (chunk) => {
      if (stderrBytes < OUTPUT_CAP_BYTES) {
        stderrChunks.push(chunk)
        stderrBytes += chunk.length
      }
    })
    child.on('error', (error) => {
      stderrChunks.push(Buffer.from(`[spawn error] ${error.message}\n`))
      finish(126)
    })
    child.on('close', (code) => finish(code))
  })
}

async function hashTree(root) {
  const files = new Map()
  const walk = async (dir) => {
    let dirents
    try {
      dirents = await readdir(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const dirent of dirents) {
      if (files.size >= MAX_FILE_COUNT) return
      if (SKIP_DIR_NAMES.has(dirent.name)) continue
      const full = path.join(dir, dirent.name)
      if (dirent.isDirectory()) {
        await walk(full)
      } else if (dirent.isFile()) {
        try {
          const info = await stat(full)
          if (info.size > MAX_FILE_BYTES) continue
          const rel = path.relative(root, full).split(path.sep).join('/')
          files.set(rel, sha256(await readFile(full)))
        } catch {
          // skipped: unreadable or concurrently removed
        }
      }
    }
  }
  await walk(root)
  return files
}

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'bitwin_run',
    description: 'Run a command TWICE under a sanitized deterministic environment (TZ=UTC, LC_ALL=C, SOURCE_DATE_EPOCH, PYTHONHASHSEED=0; locale/terminal env stripped) and compare stdout hash, stderr hash, exit code and workspace file hashes. Verdict "bit_identical" proves reproducibility; "divergent" localizes the diverging channels. File content is compared under cwd (skipping .git, node_modules, .integrity; files up to 8MB, max 2000 files).',
    parameters: {
      command: { type: 'string', required: true, description: 'Shell command to execute twice.' },
      cwd: { type: 'string', description: 'Working directory for both runs and file hashing. Default: process cwd.' },
      timeoutMs: { type: 'number', description: 'Per-run timeout in milliseconds. Default 120000.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      const command = (args.command ?? '').trim()
      if (!command) throw new Error('command must be a non-empty string.')
      const timeoutMs = args.timeoutMs ?? DEFAULT_TIMEOUT_MS
      if (!(timeoutMs > 0)) throw new Error('timeoutMs must be a positive number.')
      const cwd = path.resolve(args.cwd ?? process.cwd())

      const runs = []
      for (let i = 0; i < 2; i++) {
        const run = await runCommand(command, { cwd, timeoutMs, signal: exec?.signal })
        run.files = await hashTree(cwd)
        runs.push(run)
      }
      const [run1, run2] = runs

      const divergences = []
      if (run1.exitCode !== run2.exitCode) {
        divergences.push({ kind: 'exit_code', run1: run1.exitCode, run2: run2.exitCode })
      }
      if (run1.stdoutHash !== run2.stdoutHash) {
        divergences.push({ kind: 'stdout', run1: run1.stdoutHash.slice(0, 16), run2: run2.stdoutHash.slice(0, 16) })
      }
      if (run1.stderrHash !== run2.stderrHash) {
        divergences.push({ kind: 'stderr', run1: run1.stderrHash.slice(0, 16), run2: run2.stderrHash.slice(0, 16) })
      }
      const keys = Array.from(new Set([...run1.files.keys(), ...run2.files.keys()])).sort()
      for (const key of keys) {
        const hash1 = run1.files.get(key)
        const hash2 = run2.files.get(key)
        if (hash1 === hash2) continue
        if (hash1 == null) divergences.push({ kind: 'file_added', path: key, hash2: hash2.slice(0, 16) })
        else if (hash2 == null) divergences.push({ kind: 'file_removed', path: key, hash1: hash1.slice(0, 16) })
        else divergences.push({ kind: 'file_hash', path: key, run1: hash1.slice(0, 16), run2: hash2.slice(0, 16) })
      }

      const verdict = divergences.length === 0 ? 'bit_identical' : 'divergent'
      return JSON.stringify({
        verdict,
        command,
        cwd,
        env: { fixed: FIXED_ENV, stripped: ['TZ', 'LANG', 'LC_*', 'TERM', 'COLUMNS', 'LINES', 'SESSIONNAME'] },
        runs: runs.map((run) => ({
          exitCode: run.exitCode,
          timedOut: run.timedOut,
          aborted: run.aborted,
          stdoutHash: run.stdoutHash.slice(0, 16),
          stderrHash: run.stderrHash.slice(0, 16),
          stdoutBytes: run.stdoutBytes,
          stderrBytes: run.stderrBytes,
          durationMs: run.durationMs,
          fileCount: run.files.size,
        })),
        checkedFiles: keys.length,
        divergences,
        note: 'durationMs is reported but excluded from the verdict: timing is not a content channel.',
      })
    },
  }))
}
