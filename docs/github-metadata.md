# GitHub repository metadata draft

## About description

Linux privilege broker. Checks requests against root-owned action rules, then uses host sudo, sudo-rs, or doas for privileged execution. Beta requests use the human password path; not externally audited.

## Topics

`sudo`, `sudo-alternative`, `privilege-escalation`, `linux-security`, `ai-agents`, `claude-code`, `openai-codex`, `agentic-ai`, `rust`, `cli`, `devsecops`, `least-privilege`, `doas`, `allowlist`

## Owner commands

```sh
gh repo edit YaminT/xudo --description "Linux privilege broker. Checks requests against root-owned action rules, then uses host sudo, sudo-rs, or doas for privileged execution. Beta requests use the human password path; not externally audited." \
  --add-topic sudo \
  --add-topic sudo-alternative \
  --add-topic privilege-escalation \
  --add-topic linux-security \
  --add-topic ai-agents \
  --add-topic claude-code \
  --add-topic openai-codex \
  --add-topic agentic-ai \
  --add-topic rust \
  --add-topic cli \
  --add-topic devsecops \
  --add-topic least-privilege \
  --add-topic doas \
  --add-topic allowlist
```

Pages is live from the `gh-pages` branch with old content. To switch after
merging this change, set Settings → Pages → Source to “GitHub Actions”, then run
the Pages workflow. Alternatively, remove the old site.

The repo's `github-pages` environment currently allows deployments only from
the `gh-pages` branch. Before the first run, the owner must go to Settings →
Environments → github-pages → Deployment branches and replace the `gh-pages`
rule with `main` only. That rule is also what blocks branch deploys
server-side.

Create a tag ruleset at Settings → Rules → Rulesets → New tag ruleset that
restricts `v*` tags to the owner. Anyone with write access could otherwise
push a release tag.

Social preview image: not made.
