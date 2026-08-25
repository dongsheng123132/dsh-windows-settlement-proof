import assert from 'node:assert/strict'
import { createDefinitions } from '../index.js'
import { readFile } from 'node:fs/promises'
const manifestJson = await readFile(new URL('../examples/settled.json', import.meta.url), 'utf8')
const definitions = createDefinitions()
assert.deepEqual(definitions.map(row => row.name), ['dsh_windows_settlement_inspect', 'dsh_windows_settlement_verify'])
const result = await definitions[0].execute({ manifestJson })
assert.equal(result.expectedSurfaceCount, 3)
process.stdout.write('plugin smoke: 2 DSH definitions, inspect ok\n')
