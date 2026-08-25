# Security policy

Please report vulnerabilities privately through GitHub Security Advisories.

The verifier accepts explicit offline JSON only. Do not submit service names, task XML, Event Log payloads, command lines, credentials or business content; provide SHA-256 references. The implementation runs no external command and performs no Windows mutation. Filesystem verification is limited to workspace-relative non-symlink manifests and an explicit workspace-relative artifact directory.
