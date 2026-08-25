#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { evaluateWindowsSettlementManifest, inspectWindowsSettlementManifestJson } from '../lib/windows-settlement-proof.mjs'

const [command, manifestPath] = process.argv.slice(2)
if (!['inspect', 'verify'].includes(command) || !manifestPath) { process.stderr.write('Usage: dsh-windows-settlement-proof <inspect|verify> <manifest.json>\n'); process.exit(2) }
try { const json = await readFile(manifestPath, 'utf8'); const result = command === 'inspect' ? inspectWindowsSettlementManifestJson(json) : evaluateWindowsSettlementManifest(json); process.stdout.write(`${JSON.stringify(result)}\n`); process.exitCode = command === 'verify' && result.verdict !== 'settled' ? 1 : 0 } catch (error) { process.stdout.write(`${JSON.stringify({ ok: false, error: { code: error.code || 'ERROR' } })}\n`); process.exitCode = 2 }
