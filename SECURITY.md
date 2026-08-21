# Security Policy

## Reporting a vulnerability

Email **support@veraqis.tech** with steps to reproduce and the affected
version. Please don't open a public issue for a security report — we'll
acknowledge your report and work with you on a fix and disclosure timeline.

## Scope

This repository is a structural archive-repair engine and CLI: it reads
untrusted, possibly-damaged archive files and writes recovered output to a
location you choose. Relevant reports include (but aren't limited to):

- A crash, panic, or hang on malformed or adversarial input.
- A case where recovered output doesn't match what its own checksum proves
  (i.e. verified-recovered bytes that are actually wrong).
- Path traversal or unintended filesystem writes from a crafted archive.
- Any way to exceed documented resource limits (memory, output size) via a
  crafted input.

This tool never makes network calls and holds no credentials or secrets;
reports about those categories don't apply here.

## Supported versions

This is an actively developed, pre-1.0 project. Security fixes land on the
latest commit; there is no separate long-term-support branch.
