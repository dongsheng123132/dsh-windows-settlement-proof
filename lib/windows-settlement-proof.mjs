import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 4 * 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/
const SURFACES = new Set(['service-config', 'service-runtime', 'task-definition', 'task-runtime', 'event-record', 'policy-projection'])
const SECRET_VALUE = /(?:bearer\s+[a-z0-9._-]{12,}|(?:sk|ghp|github_pat)_[a-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i
const stable = value => JSON.stringify(value, (_, child) => child && typeof child === 'object' && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a.localeCompare(b))) : child)
export const sha256 = value => createHash('sha256').update(value).digest('hex')
const fail = (code, message) => Object.assign(new Error(message), { code })
const boundedId = (value, label) => { if (typeof value !== 'string' || !ID.test(value)) throw fail('INVALID_MANIFEST', `${label} must be a bounded public id`) }
const hash = (value, label) => { if (!HEX.test(value || '')) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const timestamp = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return parsed }

function rejectSecretValues(value, path = '$') {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) throw fail('SECRET_MATERIAL', `secret-shaped value rejected at ${path}`)
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (/(?:secret|password|credential|api[_-]?key|private[_-]?key|auth(?:orization)?|cookie)$/i.test(key) && (typeof child === 'string' || typeof child === 'number')) throw fail('SECRET_MATERIAL', `credential field rejected at ${path}.${key}`)
    rejectSecretValues(child, `${path}.${key}`)
  }
}

function parseManifest(input) {
  let manifest
  try { manifest = typeof input === 'string' ? JSON.parse(input) : structuredClone(input) } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!manifest || manifest.schemaVersion !== 1) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required')
  rejectSecretValues(manifest)
  boundedId(manifest.proofId, 'proofId'); boundedId(manifest.change?.targetRevision, 'change.targetRevision')
  for (const key of ['targetHash', 'requestSha256', 'approvalSha256', 'desiredStateSha256']) hash(manifest.change?.[key], `change.${key}`)
  const evaluationMs = timestamp(manifest.evaluationTime, 'evaluationTime')
  const requestedMs = timestamp(manifest.change.requestedAt, 'change.requestedAt')
  const approvedMs = timestamp(manifest.change.approvedAt, 'change.approvedAt')
  if (approvedMs < requestedMs) throw fail('INVALID_CHRONOLOGY', 'approval predates request')
  const maxAgeMs = manifest.policy?.maxObservationAgeMs
  if (!Number.isInteger(maxAgeMs) || maxAgeMs < 1000 || maxAgeMs > 365 * 86400000) throw fail('INVALID_MANIFEST', 'maxObservationAgeMs is out of range')
  const minimumRestartEpoch = manifest.policy?.minimumRestartEpoch
  if (!Number.isInteger(minimumRestartEpoch) || minimumRestartEpoch < 0 || minimumRestartEpoch > 32) throw fail('INVALID_MANIFEST', 'minimumRestartEpoch must be 0..32')
  if (typeof manifest.policy?.requireSuccessEvent !== 'boolean') throw fail('INVALID_MANIFEST', 'requireSuccessEvent must be boolean')
  if (!Array.isArray(manifest.expectedSurfaces) || !manifest.expectedSurfaces.length || manifest.expectedSurfaces.length > SURFACES.size) throw fail('INVALID_MANIFEST', 'expectedSurfaces must contain 1..6 entries')
  if (!Array.isArray(manifest.observations) || !manifest.observations.length || manifest.observations.length > SURFACES.size) throw fail('INVALID_MANIFEST', 'observations must contain 1..6 entries')
  const expected = new Map()
  for (const row of manifest.expectedSurfaces) {
    if (!SURFACES.has(row?.surface)) throw fail('INVALID_MANIFEST', 'unsupported expected surface')
    hash(row.expectedStateSha256, 'expectedStateSha256')
    if (expected.has(row.surface)) throw fail('INVALID_MANIFEST', 'duplicate expected surface')
    expected.set(row.surface, row)
  }
  const observations = new Map()
  for (const row of manifest.observations) {
    boundedId(row?.id, 'observation.id')
    if (!SURFACES.has(row.surface)) throw fail('INVALID_MANIFEST', 'unsupported observation surface')
    if (observations.has(row.surface)) throw fail('INVALID_MANIFEST', 'duplicate observation surface')
    for (const key of ['targetHash', 'desiredStateSha256', 'observedStateSha256', 'sourceSha256']) hash(row[key], `observation.${key}`)
    boundedId(row.targetRevision, 'observation.targetRevision')
    if (!['applied', 'failed', 'unknown'].includes(row.outcome)) throw fail('INVALID_MANIFEST', 'observation.outcome is invalid')
    if (!Number.isInteger(row.restartEpoch) || row.restartEpoch < 0 || row.restartEpoch > 1000000) throw fail('INVALID_MANIFEST', 'observation.restartEpoch is invalid')
    const capturedMs = timestamp(row.capturedAt, 'observation.capturedAt')
    observations.set(row.surface, { row, capturedMs })
  }
  return { manifest, evaluationMs, approvedMs, expected, observations }
}

export function inspectWindowsSettlementManifestJson(manifestJson) {
  const { manifest } = parseManifest(manifestJson)
  return {
    schemaVersion: 1,
    proofIdHash: sha256(manifest.proofId),
    targetHash: manifest.change.targetHash,
    targetRevisionHash: sha256(manifest.change.targetRevision),
    expectedSurfaceCount: manifest.expectedSurfaces.length,
    observationCount: manifest.observations.length,
    minimumRestartEpoch: manifest.policy.minimumRestartEpoch,
    returnsWindowsPayloads: false,
    executesExternalCommands: false
  }
}

export function evaluateWindowsSettlementManifest(manifestJson) {
  const { manifest, evaluationMs, approvedMs, expected, observations } = parseManifest(manifestJson)
  const missingSurfaceHashes = [...expected.keys()].filter(surface => !observations.has(surface)).map(sha256).sort()
  const unexpectedSurfaceHashes = [...observations.keys()].filter(surface => !expected.has(surface)).map(sha256).sort()
  const surfaces = [...expected.entries()].filter(([surface]) => observations.has(surface)).map(([surface, lock]) => {
    const { row, capturedMs } = observations.get(surface)
    const identityMatched = row.targetHash === manifest.change.targetHash && row.targetRevision === manifest.change.targetRevision
    const desiredLockMatched = row.desiredStateSha256 === manifest.change.desiredStateSha256
    const stateMatched = row.observedStateSha256 === lock.expectedStateSha256
    const chronological = capturedMs >= approvedMs && capturedMs <= evaluationMs
    const fresh = chronological && evaluationMs - capturedMs <= manifest.policy.maxObservationAgeMs
    const restartSatisfied = row.restartEpoch >= manifest.policy.minimumRestartEpoch
    const applied = row.outcome === 'applied'
    return { surfaceHash: sha256(surface), observationIdHash: sha256(row.id), sourceSha256: row.sourceSha256, identityMatched, desiredLockMatched, stateMatched, chronological, fresh, restartEpoch: row.restartEpoch, restartSatisfied, applied, settled: identityMatched && desiredLockMatched && stateMatched && fresh && restartSatisfied && applied }
  }).sort((a, b) => a.surfaceHash.localeCompare(b.surfaceHash))
  const successEventPresent = !manifest.policy.requireSuccessEvent || (observations.get('event-record')?.row.outcome === 'applied' && expected.has('event-record'))
  const exactSurfaceSet = missingSurfaceHashes.length === 0 && unexpectedSurfaceHashes.length === 0
  const settled = exactSurfaceSet && successEventPresent && surfaces.every(row => row.settled)
  return {
    schemaVersion: 1,
    verdict: settled ? 'settled' : 'unsettled',
    proofIdHash: sha256(manifest.proofId),
    targetHash: manifest.change.targetHash,
    targetRevisionHash: sha256(manifest.change.targetRevision),
    requestSha256: manifest.change.requestSha256,
    approvalSha256: manifest.change.approvalSha256,
    desiredStateSha256: manifest.change.desiredStateSha256,
    checks: { exactSurfaceSet, successEventPresent, allSurfacesSettled: surfaces.every(row => row.settled) },
    disclosures: { missingSurfaceHashes, unexpectedSurfaceHashes },
    surfaces,
    returnsWindowsPayloads: false,
    executesExternalCommands: false,
    destructiveActions: false
  }
}

async function safeManifest(root, manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath || manifestPath.length > 512 || isAbsolute(manifestPath)) throw fail('PATH_ESCAPE', 'manifestPath must be bounded and workspace-relative')
  const absolute = resolve(root, manifestPath); const rel = relative(root, absolute)
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'manifestPath escapes workspaceRoot')
  let cursor = root; let stat
  const parts = rel.split(/[\\/]/)
  for (const [index, part] of parts.entries()) { cursor = resolve(cursor, part); stat = await lstat(cursor).catch(() => { throw fail('MISSING_MANIFEST', 'manifest is missing') }); if (stat.isSymbolicLink()) throw fail('UNSAFE_MANIFEST', 'manifest path must contain no symlink'); if (index < parts.length - 1 && !stat.isDirectory()) throw fail('UNSAFE_MANIFEST', 'manifest parent must be a real directory') }
  if (!stat.isFile()) throw fail('UNSAFE_MANIFEST', 'manifest must be a regular file')
  if (stat.size > MAX_FILE) throw fail('FILE_TOO_LARGE', 'manifest exceeds 4 MiB')
  const rootReal = await realpath(root); const fileReal = await realpath(absolute); const realRel = relative(rootReal, fileReal)
  if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real manifest path escapes workspaceRoot')
  return readFile(fileReal, 'utf8')
}

async function safeArtifactDir(root, artifactDir) {
  if (typeof artifactDir !== 'string' || !artifactDir || artifactDir.length > 512 || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be bounded and workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir)
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root
  for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

export async function verifyWindowsSettlementManifest({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot)
  const report = evaluateWindowsSettlementManifest(await safeManifest(root, manifestPath))
  const bytes = Buffer.from(`${stable(report)}\n`)
  const digest = sha256(bytes)
  const dir = await safeArtifactDir(root, artifactDir)
  const output = resolve(dir, `windows-settlement-proof-${digest}.json`)
  try { await writeFile(output, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; const existing = await readFile(output); if (!existing.equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(output)
  if (sha256(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back verification failed')
  return { ...report, artifact: { path: relative(root, output).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
