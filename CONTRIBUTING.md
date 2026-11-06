# Contributing

Start with `just setup`, then run `just verify` before committing. The complete
engineering and security rules, including commit message rules, are in
[CLAUDE.md](CLAUDE.md); follow them rather than duplicating them here.

Some lanes need Docker: `just linux-test`, `just root-test`, `just units`,
`just differential`, `just install-root`, `just deb-test`, and
`just systemd-test`. `just ci` includes several of these lanes. Check the
relevant recipe before running it; lanes may need network access too.

Do not bypass the pre-commit hook (`--no-verify`) or CI gates. Use Conventional
Commits with an imperative subject of at most 50 characters. Security-relevant
changes must name the threat and the test that covers it in the commit body.
