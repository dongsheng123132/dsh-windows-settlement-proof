import { inspectWindowsSettlementManifestJson, verifyWindowsSettlementManifest } from './lib/windows-settlement-proof.mjs'

export const name = 'dsh-windows-settlement-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const define = value => ({ ...value, output: { schema: {}, render: renderJson } })

export function createDefinitions(_ctx = {}, config = {}) {
  const workspaceRoot = config.workspaceRoot || process.cwd()
  return [
    define({ name: 'dsh_windows_settlement_inspect', description: 'Inspect bounded counts and hashes from an explicit Windows settlement manifest without returning Windows payloads.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectWindowsSettlementManifestJson(manifestJson) }),
    define({ name: 'dsh_windows_settlement_verify', description: 'Verify offline Windows control-plane receipts against approved hashes and write a content-addressed redacted report.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async args => verifyWindowsSettlementManifest({ workspaceRoot, ...args }) })
  ]
}

export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
