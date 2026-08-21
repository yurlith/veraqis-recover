# Contributing

Thanks for considering a contribution. This project accepts pull requests.

## Before you start

For anything beyond a small fix (a typo, an obvious bug), please open an
issue first to discuss the change — it saves you writing code that doesn't
end up landing.

## Developer Certificate of Origin

Every commit must be signed off, certifying you wrote it or otherwise have
the right to submit it under this project's license. Read the full text in
[`DCO`](DCO) — it's the standard Developer Certificate of Origin used by the
Linux kernel and many other projects, not something specific to this repo.

Add the sign-off automatically with `-s`:

```sh
git commit -s -m "your commit message"
```

This appends a `Signed-off-by: Your Name <your.email@example.com>` trailer
using your configured `git config user.name` / `user.email`. Pull requests
with unsigned commits are rejected by CI.

## Making a change

1. Fork the repository and create a branch.
2. Make your change, with tests for new behavior or a regression test for a
   bug fix.
3. `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and
   `cargo test --workspace` should all pass locally before you open a PR.
4. Open the PR against `main` with a clear description of what changed and
   why.

## Scope

This repository is the open structural-repair core of a larger engine (see
[README.md](README.md)). Contributions that extend structural repair for
ZIP/gzip/tar/RAR5/7z, fix bugs, improve tests, or improve documentation are
welcome. Contributions that would require the closed pieces this repository
deliberately excludes (see the README) are out of scope here.

## Security issues

Please don't open a public issue for a security report — see
[SECURITY.md](SECURITY.md) instead.
