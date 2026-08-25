import { access, readFile } from 'node:fs/promises'
const required = ['.codex-plugin/plugin.json', '.mcp.json', 'cordis.patch.yml', 'index.js', 'mcp-server.mjs', 'LICENSE', 'README.md', 'README.zh-CN.md', 'SECURITY.md', 'examples/settled.json']
for (const file of required) await access(new URL(`../${file}`, import.meta.url))
const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
const plugin = JSON.parse(await readFile(new URL('../.codex-plugin/plugin.json', import.meta.url), 'utf8'))
if (pkg.name !== plugin.name || !pkg.dsh?.bundle?.patch || !plugin.mcpServers) throw new Error('package/plugin integration mismatch')
const source = await readFile(new URL('../lib/windows-settlement-proof.mjs', import.meta.url), 'utf8')
if (/child_process|exec\(|spawn\(|powershell|sc\.exe|reg\.exe/i.test(source)) throw new Error('core must not execute Windows commands')
process.stdout.write('check: structure, manifests, DSH bundle and no-command core ok\n')
