import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = fileURLToPath(new URL('..', import.meta.url))
const PLUGINS = [
  'dsh-integrity-prereg',
  'dsh-integrity-bitwin',
  'dsh-integrity-adjudicate',
  'dsh-integrity-provenance',
  'dsh-integrity-guardrail',
]
const DSH_TOOLS_PIN = '0.1.1-rc.2'

const failures = []
const checks = []

function check(condition, message) {
  checks.push(message)
  if (!condition) failures.push(message)
}

for (const plugin of PLUGINS) {
  const dir = path.join(repoRoot, 'plugins', plugin)
  const pkgPath = path.join(dir, 'package.json')

  const raw = await readFile(pkgPath, 'utf8').catch(() => null)
  if (raw == null) {
    failures.push(`${plugin}: package.json missing`)
    continue
  }
  const pkg = JSON.parse(raw)

  check(pkg.name === plugin, `${plugin}: package name matches directory`)
  check(pkg.version === '0.1.0', `${plugin}: version 0.1.0`)
  check(pkg.type === 'module', `${plugin}: type module`)
  check(pkg.main === 'index.js', `${plugin}: main index.js`)
  check(pkg.license === 'Apache-2.0', `${plugin}: Apache-2.0`)
  check(pkg.engines?.node != null, `${plugin}: engines.node declared`)
  check(
    pkg.dependencies?.['@deepseek-ai/dsh-tools'] === DSH_TOOLS_PIN,
    `${plugin}: dsh-tools pinned exactly to ${DSH_TOOLS_PIN}`,
  )
  check(pkg.dsh?.bundle?.patch === './cordis.patch.yml', `${plugin}: dsh.bundle.patch -> cordis.patch.yml`)
  check(
    JSON.stringify(pkg.files) === JSON.stringify(['index.js', 'cordis.patch.yml', 'README.md']),
    `${plugin}: files field exact`,
  )

  const index = await readFile(path.join(dir, 'index.js'), 'utf8').catch(() => null)
  check(index != null, `${plugin}: index.js exists`)
  if (index != null) {
    check(index.includes(`export const name = '${plugin.replace(/^dsh-/, '')}'`), `${plugin}: plugin name export`)
    check(index.includes('export function apply'), `${plugin}: apply export`)
    check(index.includes("from '@deepseek-ai/dsh-tools'"), `${plugin}: imports dsh-tools`)
  }

  const patch = await readFile(path.join(dir, 'cordis.patch.yml'), 'utf8').catch(() => null)
  check(patch != null, `${plugin}: cordis.patch.yml exists`)
  if (patch != null) {
    check(patch.includes(`name: ${plugin}`), `${plugin}: patch row references package name`)
  }

  const readme = await readFile(path.join(dir, 'README.md'), 'utf8').catch(() => null)
  check(readme != null, `${plugin}: README.md exists`)
}

console.log(`package checks: ${checks.length} run, ${failures.length} failed`)
for (const failure of failures) {
  console.error(`FAIL: ${failure}`)
}
process.exit(failures.length === 0 ? 0 : 1)
