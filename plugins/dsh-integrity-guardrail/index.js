import { createHash } from 'node:crypto'
import { appendFile, mkdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'integrity-guardrail'
export const inject = ['tools']

const INTEGRITY_TOOLS = new Set([
  'prereg_register', 'prereg_list', 'prereg_verify',
  'adjudicate',
  'provenance_record', 'provenance_verify',
  'bitwin_run',
  'guardrail_status',
])

const MUTATION_TOOLS = /^(write|edit|delete|remove|move|rename|save|patch|truncate)$/
const SHELLISH_TOOLS = /bash|shell|exec|run|terminal|command/i

const DEFAULT_DENY_PATTERNS = [
  { id: 'rm-root', pattern: /\brm\b[^|;&]*\s(\/|~|\.|\*|\$HOME)(\s|$)/ },
  { id: 'mkfs', pattern: /\bmkfs(\.[a-z0-9]+)?\b/i },
  { id: 'dd-raw-disk', pattern: /\bdd\b[^|;&]*\bof=\/dev\/(sd|nvme|disk|hd)/i },
  { id: 'pipe-to-shell', pattern: /\b(curl|wget|iwr|invoke-webrequest)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|ksh|pwsh|powershell|cmd)(\.exe)?(\s|$)/i },
  { id: 'sudo', pattern: /\bsudo\s+\S/ },
  { id: 'win-rd-s', pattern: /\b(rd|rmdir)\s+\/s\b/i },
  { id: 'win-del-s', pattern: /\bdel\s+\/[sq]\b/i },
  { id: 'win-format', pattern: /\bformat\s+[c-z]:/i },
  { id: 'win-remove-item-drive', pattern: /\bremove-item\b(?=[^|;&]*\b-recurse\b)(?=[^|;&]*\b-force\b)(?=[^|;&]*[c-z]:[\\/])/i },
  { id: 'shutdown', pattern: /\b(shutdown|poweroff|reboot|halt)\b(?=[\s/]|$)/i },
  { id: 'env-file', pattern: /\.env(\.[a-z0-9_-]+)?(?=[\\/"'\s:]|$)/ },
  { id: 'ssh-cred-file', pattern: /(^|[\\/"'\s=:,])(id_rsa|id_ed25519|id_ecdsa|authorized_keys|\.netrc|\.npmrc|\.aws.{0,2}credentials)([\\/"'\s:]|$)/ },
  { id: 'git-force-main', pattern: /\bgit\s+push\b(?=[^|;&]*(--force(-with-lease)?\b|-f\b))(?=[^|;&]*\b(main|master)\b)/i },
  { id: 'chmod-root', pattern: /\bchmod\s+(-[a-z]+\s+)*777\s+\/(\s|$)/ },
  { id: 'etc-passwd-write', pattern: /\b(cp|mv|tee|sed)\b[^|;&]*\/etc\/(passwd|shadow|sudoers)\b|>\s*\/etc\/(passwd|shadow|sudoers)\b/ },
]

const escapeRe = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

const sha256 = (text) => createHash('sha256').update(text).digest('hex')

function subjectTexts(exec) {
  const texts = []
  const args = exec?.arguments
  if (typeof args === 'string') {
    texts.push(args)
  } else if (args != null) {
    texts.push(JSON.stringify(args))
    for (const value of Object.values(args)) {
      if (typeof value === 'string') texts.push(value)
      else if (value != null && typeof value === 'object') texts.push(JSON.stringify(value))
    }
  }
  return texts
}

function findDeny(exec, texts, denyPatterns) {
  for (const entry of denyPatterns) {
    if (texts.some((text) => entry.pattern.test(text))) {
      return { id: entry.id, reason: `tool "${exec.name}" matches deny pattern "${entry.id}"` }
    }
  }
  return null
}

function integrityStoreViolation(exec, texts, integrityStoreDir) {
  const dirHit = texts.some((text) => text.includes(integrityStoreDir))
  if (!dirHit) return null
  if (MUTATION_TOOLS.test(exec.name)) {
    return {
      id: 'integrity-store-write',
      reason: `tool "${exec.name}" targets the integrity store "${integrityStoreDir}"; only integrity tools may write there`,
    }
  }
  if (SHELLISH_TOOLS.test(exec.name)) {
    const dirRe = new RegExp(escapeRe(integrityStoreDir))
    const mutationRe = /\b(rm|rmdir|mv|cp|truncate|tee|sed|chmod|del|rd)\b[^|;&]{0,400}/
    const redirectRe = new RegExp(`>{1,2}\\s*\\S*${escapeRe(integrityStoreDir)}`)
    for (const text of texts) {
      if ((mutationRe.test(text) && dirRe.test(text)) || redirectRe.test(text)) {
        return {
          id: 'integrity-store-write',
          reason: `command writes into the integrity store "${integrityStoreDir}"; only integrity tools may write there`,
        }
      }
    }
  }
  return null
}

function toArray(value, field) {
  if (value == null) return []
  if (!Array.isArray(value)) {
    throw new Error(`dsh-integrity-guardrail: ${field} must be an array of regex source strings.`)
  }
  return value.map((entry) => {
    if (typeof entry !== 'string' || entry.trim() === '') {
      throw new Error(`dsh-integrity-guardrail: ${field} entries must be non-empty regex source strings.`)
    }
    return entry
  })
}

function compilePatterns(sources, field) {
  return sources.map((source, index) => {
    try {
      return { id: `${field}-${index + 1}`, pattern: new RegExp(source) }
    } catch (error) {
      throw new Error(`dsh-integrity-guardrail: invalid regex in ${field}[${index}] (${source}): ${error.message}`)
    }
  })
}

function normalizeConfig(raw) {
  const config = raw == null || typeof raw !== 'object' ? {} : raw
  const mode = config.mode ?? 'enforce'
  if (mode !== 'enforce' && mode !== 'audit') {
    throw new Error(`dsh-integrity-guardrail: mode must be "enforce" or "audit", got ${JSON.stringify(mode)}.`)
  }
  const integrityStoreDir = String(config.integrityStoreDir ?? '.integrity')
  return {
    mode,
    denyPatterns: [
      ...DEFAULT_DENY_PATTERNS,
      ...compilePatterns(toArray(config.extraDenyPatterns, 'extraDenyPatterns'), 'extraDeny'),
    ],
    allowPatterns: compilePatterns(toArray(config.allowPatterns, 'allowPatterns'), 'allow'),
    integrityStoreDir,
    protectIntegrityStores: config.protectIntegrityStores ?? true,
    auditLog: config.auditLog ?? true,
    auditPath: path.resolve(String(config.auditPath ?? '.integrity/tool-audit.jsonl')),
  }
}

function createAuditLog(auditPath) {
  let lastHash = null
  let count = 0
  let initPromise = null
  let queue = Promise.resolve()

  const init = () => {
    if (initPromise == null) {
      initPromise = (async () => {
        let text = ''
        try {
          text = await readFile(auditPath, 'utf8')
        } catch (error) {
          if (error?.code !== 'ENOENT') throw error
        }
        for (const line of text.split(/\r?\n/)) {
          if (!line.trim()) continue
          try {
            const parsed = JSON.parse(line)
            if (typeof parsed.hash === 'string') {
              lastHash = parsed.hash
              count++
            }
          } catch {
            // skip malformed legacy lines
          }
        }
      })()
    }
    return initPromise
  }

  const write = async (event) => {
    const record = {
      at: new Date().toISOString(),
      kind: event.kind,
      name: event.name,
      isError: event.isError ?? false,
      callId: event.callId ?? null,
      detail: event.detail ?? null,
      prevHash: lastHash,
    }
    record.hash = sha256(JSON.stringify({
      at: record.at,
      kind: record.kind,
      name: record.name,
      isError: record.isError,
      callId: record.callId,
      detail: record.detail,
      prevHash: record.prevHash,
    }))
    await mkdir(path.dirname(auditPath), { recursive: true })
    await appendFile(auditPath, JSON.stringify(record) + '\n', 'utf8')
    lastHash = record.hash
    count++
  }

  return {
    append(event) {
      queue = queue
        .then(() => init())
        .then(() => write(event))
        .catch(() => {})
      return queue
    },
    status: () => ({ auditPath, count, lastHash }),
  }
}

export function apply(ctx, rawConfig) {
  const cfg = normalizeConfig(rawConfig)
  const audit = createAuditLog(cfg.auditPath)

  ctx.on('tools/pre-execute', async (exec, next) => {
    const texts = subjectTexts(exec)
    if (texts.length === 0) return next()

    const allowHit = cfg.allowPatterns.some((entry) => texts.some((text) => entry.pattern.test(text)))
    if (!allowHit) {
      const violation = findDeny(exec, texts, cfg.denyPatterns)
        ?? (cfg.protectIntegrityStores ? integrityStoreViolation(exec, texts, cfg.integrityStoreDir) : null)
      if (violation) {
        await audit.append({
          kind: cfg.mode === 'enforce' ? 'deny' : 'would-deny',
          name: exec?.name ?? 'unknown',
          callId: exec?.callId ?? null,
          detail: `[${violation.id}] ${violation.reason}`,
        })
        if (cfg.mode === 'enforce') {
          return {
            kind: 'deny',
            reason: `Denied by dsh-integrity-guardrail [${violation.id}]: ${violation.reason}. Fix the call, or add an allowPattern if this is intentional.`,
          }
        }
      }
    }
    return next()
  })

  ctx.on('tools/result', (...args) => {
    if (!cfg.auditLog) return
    try {
      let name = 'unknown'
      let isError = false
      let callId = null
      for (const arg of args) {
        if (arg != null && typeof arg === 'object') {
          name = arg.name ?? arg.toolName ?? name
          isError = Boolean(arg.isError ?? (arg.error != null)) || isError
          callId = arg.callId ?? arg.id ?? callId
        }
      }
      void audit.append({ kind: 'tool_result', name, isError, callId })
    } catch {
      // audit must never break the tool loop
    }
  })

  ctx.tools.register(defineTool({
    name: 'guardrail_status',
    description: 'Report the active dsh-integrity-guardrail configuration: mode, deny pattern ids, allow pattern ids, integrity store protection, and audit log statistics (record count and latest hash prefix).',
    parameters: {},
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute() {
      const status = audit.status()
      return JSON.stringify({
        plugin: 'dsh-integrity-guardrail',
        mode: cfg.mode,
        denyPatterns: cfg.denyPatterns.map((entry) => entry.id),
        allowPatterns: cfg.allowPatterns.map((entry) => entry.id),
        protectIntegrityStores: cfg.protectIntegrityStores,
        integrityStoreDir: cfg.integrityStoreDir,
        auditLog: cfg.auditLog,
        auditPath: status.auditPath,
        auditRecords: status.count,
        lastAuditHash: status.lastHash?.slice(0, 12) ?? null,
      })
    },
  }))
}
