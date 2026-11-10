# Contributing

Start with `just setup`, then run `just verify` before committing. Coverage is
100% on lines, regions, and functions; a waiver is an attribute on the item
plus a comment naming a concrete reason. The product invariants are in
[howiwork.md](howiwork.md). Follow them rather than duplicating them here.

Some lanes need Docker: `just linux-test`, `just root-test`, `just units`,
`just differential`, `just install-root`, `just deb-test`, and
`just systemd-test`. `just ci` includes several of these lanes. Check the
relevant recipe before running it; lanes may need network access too.

Do not bypass the pre-commit hook (`--no-verify`) or CI gates. Use Conventional
Commits with an imperative subject of at most 50 characters. Security-relevant
changes must name the threat and the test that covers it in the commit body.
