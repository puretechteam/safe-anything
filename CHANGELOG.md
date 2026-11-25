# Changelog

## Unreleased

- Config: `config.gha-script-injection` also reports `workflow_run` fields that the triggering fork controls:
  `head_branch`, `display_title`, `head_commit.message`, `head_repository.name` and `.description`, and
  `pull_requests[n].head.ref`, plus `check_suite.head_branch` (also under `check_run`). `id`, `conclusion`, the base
  `repository` and `pull_requests[n].base` stay quiet. A `description` field is now read for the other events too.
- Agent: `agent.mcp-plaintext-secret` also checks the `headers` and `http_headers` of remote MCP servers
  in JSON configs. `Authorization` and `Proxy-Authorization` always count. In `env` and headers alike, a
  value is judged after its auth scheme and with its variables taken out: `Bearer ${API_TOKEN}` and
  `user:${PASSWORD}` are skipped, `admin:<password>@${DB_HOST}` and `${TOKEN:-sk_live_...}` are
  reported.
- Agent: `agent.unrestricted-shell` now reads `permissions.allow` in `.claude/settings*.json` instead of matching `"Bash"` anywhere in the file, so entries in `deny`, `ask`, or hook matchers are no longer flagged.
- Agent: more agent files are read: `.clinerules` (a file or a folder), `.windsurf/rules/`, `.github/instructions/*.instructions.md`,
  `.github/prompts/*.prompt.md`, `.roo/rules/` and `.kiro/steering/` for instructions, and Windsurf's `mcp_config.json`,
  `cline_mcp_settings.json`, and Zed's `.zed/settings.json` and `.config/zed/settings.json` (`context_servers`) for MCP servers.
- Agent: `agent.mcp-unpinned` skips the value of flags like `--python` (`uvx`, `pipx run`) and `--user`
  or `--platform` (`docker run`, `podman run`), so `uvx --python 3.12 pkg==1.0` no longer reports `3.12`
  and `docker run -u 1000:1000 acme/mcp` reports `acme/mcp`. An empty `docker run` argument is skipped.
- Secrets: `secret.env-not-ignored` is reported at the `.env` file when the project has no `.gitignore`
  at all. Example files like `.env.example` alone no longer trigger it.
- Secrets: `secret.env-not-ignored` reads `.gitignore` the way git does, so only a line that really ignores
  `.env` counts. `.envrc`, `.env.local`, `.env/`, `# .env` or a later `!.env` no longer hide it.
- Secrets: `secret.env-file` and `secret.env-example-value` now catch base64 values ending in `=` padding and
  passwords with `!@#$%^&*`. A value that is only `*` characters or starts with `$` (a reference like
  `$POSTGRES_PASSWORD`) is skipped.
- Secrets: `secret.public-env-secret` now replaces everything after the variable name on its line with `****`,
  so its finding no longer prints the value, however it is written (`=`, `:`, `=>`,
  `||`, `ENV NAME value`, ...). Before, the whole line was printed as is. Masking now keeps at most a third of a
  secret, so a short value is not printed whole.
- Agent: an MCP config whose `npx` (or `pnpm dlx`) argument is empty or starts with a non-ASCII
  character no longer crashes the scan.
- Scan: minified bundles, source maps, `.jsonl` and `.log` files, and images, fonts, archives, media and
  compiled files (`png`, `woff2`, `zip`, `mp4`, `class`, ...) are skipped by name without being opened.
  Other binary files are left after their first 8 KB instead of being read in full.
- Agent: `agent.mcp-plaintext-secret` no longer takes an env key for a secret when its credential word is
  only part of an ordinary word, so `PATH`, `PYTHONPATH`, `NODE_PATH`, `DISPATCH_MODE`, `AUTHOR`,
  `MONKEY_PATCH` and `KEYCHAIN_PROFILE` are not reported. `GITHUB_PAT`, `githubPat`, `OPENAI_APIKEY`,
  `daemonKey`, `patHash` and `clientSecret` still are.
- Agent: `agent.mcp-insecure-url` now reads a bracketed IPv6 host up to its closing `]` (only `[::1]` counts as local) and matches `http://` without regard to case.
- Dependencies: `pubspec.lock` is read, so Dart and Flutter packages are checked against OSV.dev
  (`Pub` ecosystem). Packages from the `sdk` source, like `flutter`, are skipped.
- Secrets: new rule `secret.gitlab-token` (critical) for GitLab personal access tokens (`glpat-` followed by 20 characters).
- Secrets: new rule `secret.huggingface-token` (critical) for Hugging Face access tokens (`hf_` followed by 34 letters).
- Secrets: new rule `secret.npm-token` (critical) for npm access tokens (`npm_` followed by 36 letters or digits).
- Secrets: new rule `secret.mailgun-key` (critical) for Mailgun private API keys (`key-` followed by 32 lowercase hex characters).
- Secrets: new rule `secret.telegram-bot-token` (high) for Telegram bot tokens (8 to 10 digits, a colon, then 35 letters, digits, `_` or `-`).
- Secrets: new rule `secret.aws-secret-key` (critical) for AWS secret access keys: a 40-character value assigned to a name with `aws` and `secret` in it
  (`aws_secret_access_key = ...`, `AWS_SECRET_ACCESS_KEY=...`, `"awsSecretAccessKey": "..."`). Values that can't be a random key are
  skipped: the AWS docs example key, hashes, paths, words like `TestSecretKey...`, `000...` and other repeats.
- Secrets: new rule `secret.twilio-api-key` (critical) for Twilio API keys (`SK` followed by 32 lowercase hex characters).
- Secrets: new rule `secret.digitalocean-token` (critical) for DigitalOcean tokens (`dop_v1_`, `doo_v1_` or `dor_v1_` followed by 64 lowercase hex characters).
- Secrets: new rule `secret.shopify-token` (critical) for Shopify access tokens (`shpat_`, `shpca_`, `shppa_` or `shpss_` followed by 32 hex characters).
- Secrets: new rule `secret.pypi-token` (critical) for PyPI upload tokens (`pypi-AgEIcHlwaS5vcmc` followed by 50 or more characters).
- Secrets: new rule `secret.sendgrid-key` (critical) for SendGrid API keys (`SG.`, 22 characters, a dot, then 43 characters).
- Secrets: new rule `secret.discord-webhook` (high) for Discord webhook URLs (`discord.com/api/webhooks/` or `discordapp.com/api/webhooks/`, a 17 to 20 digit id, then a token of 60 or more characters).
- Secrets: new rule `secret.slack-webhook` (high) for Slack incoming webhook URLs (`hooks.slack.com/services/T…/B…/` and a 24-character token). The docs placeholder with `T00000000` or `XXXXXXXX` is skipped.
- Config: new rule `config.tf-public-access-block` (medium) for `block_public_policy = false` or
  `restrict_public_buckets = false` in an `aws_s3_bucket_public_access_block` or `aws_s3_account_public_access_block`.
- Secrets: new rule `secret.groq-key` (critical) for Groq API keys (`gsk_` followed by 52 letters or digits).
- Code: new rule `code.open-redirect` (medium) for redirects built straight from request input (`res.redirect(req.query.next)`, `redirect(request.args.get("next"))`); a redirect to a fixed path stays unflagged.
- CLI: `--sarif-file <FILE>` writes SARIF to a file from the same scan that prints the report and sets the
  exit code. The GitHub Action uses it, so it scans (and asks OSV.dev) once instead of twice.
- Config: new rules `config.tf-public-database` (high) for `publicly_accessible = true` and `config.tf-unencrypted-storage` (medium)
  for `storage_encrypted = false` in Terraform files. `publicly_accessible = false`, `storage_encrypted = true` and commented-out lines stay unflagged.
- Config: `config.remote-script` also checks GitHub Actions workflows, so a `run:` step (or a line in a
  `run: |` block) that pipes `curl` or `wget` into a shell is reported. `curl -o file URL`, a step `name:` and a
  commented-out line are not.
- Code: `code.sql-injection` also catches Go queries built by concatenation in `db.Query`, `db.QueryRow`, `db.Exec`
  and their `Context` variants (`db.Query("SELECT * FROM t WHERE id=" + id)`). A query with a placeholder stays unflagged.
- Code: `code.ssrf` also covers Go (`http.Get`, `http.Head`, `http.Post` with `r.FormValue(...)` or `r.URL.Query().Get(...)`)
  and PHP (`file_get_contents`, `curl_init`, `fopen` with `$_GET`, `$_POST` or `$_REQUEST`). A fixed URL stays unflagged.
- Code: `code.open-redirect` now also matches a status code first, so `res.redirect(301, req.query.next)` is reported; a redirect to a fixed path stays unflagged.
- Dependencies: `uv.lock` entries whose `source` is `editable`, `virtual` or `path` (the project itself or a
  local package) are no longer counted or looked up on PyPI.
- Dependencies: `Gemfile.lock` gems from `GIT` and `PATH` sections (a git repository or a local folder) are
  no longer counted or looked up on RubyGems. Only gems in `GEM` sections are.
- Secrets: `secret.url-credentials` skips a connection string whose password is an angle-bracket placeholder
  such as `mongodb+srv://<username>:<password>@host/db`, the form MongoDB Atlas shows in its docs.
- Secrets: `secret.private-key` also finds a key written with `\n` escapes inside a string, the way a Google
  service-account JSON file stores it. The whole key body is masked in the output.
- Dependencies: `pnpm-lock.yaml` is read again. A blank line ended the `packages:` section, and
  pnpm writes one right after it, so every pnpm project reported 0 packages checked.
- Agent: new rule `agent.mcp-auto-approve` (high) for `"enableAllProjectMcpServers": true` in
  `.claude/settings*.json`, which starts every MCP server in the project's `.mcp.json` without asking about
  each one.
- CLI: `safe-anything:ignore` takes an optional list of rule ids (`// safe-anything:ignore code.weak-hash, code.eval`)
  and then silences only those rules on that line and the next. An unknown id silences nothing. A bare marker
  still silences every rule.
- CLI: `--write-baseline <file>` records the current findings (rule, path and a SHA-256 of the line, no code or
  secrets), and `--baseline <file>` hides them, wherever the line moved to, and says how many it hid, so CI can
  fail only on new findings. The action has a `baseline` input for it.
- CLI: `--sarif` writes paths from the working directory, not from the scanned folder, so
  `safe-anything app --sarif` (or the action's `path: app`) gives `app/src/x.js` and code scanning finds
  the file. The terminal and `--json` reports keep paths relative to the scanned folder.
- CLI: SARIF rules have a `fullDescription` and a `help` text (the fix, the CWE and OWASP category, and the
  link), so a GitHub code scanning alert shows the fix in its side panel. `--list-rules --json` and the MCP
  `list_rules` tool include each rule's `fix`.
- CLI: `safe-anything --help` now shows a few examples, including `safe-anything mcp`, and how to ignore a finding (`safe-anything:ignore` or `.safe-anything-ignore`).
- Secrets: new rule `secret.google-oauth-secret` (high) for Google OAuth client secrets (`GOCSPX-` followed by 28 letters, digits, `_` or `-`).
- Dependencies: `Pipfile.lock` is read, so Pipenv projects are checked against OSV.dev (`PyPI` ecosystem), `default` and `develop` packages alike. Entries from git, a path or an editable install are skipped.

## 1.0.2 (2026-11-23)

- README: GIFs of a real Next.js finding (a password behind `NEXT_PUBLIC_`) and of a clean scan of express.

## 1.0.1 (2026-11-22)

- README and package pages name XSS and SQL injection up front.
- Issue templates (false positive or missed finding, bug, new rule) and a pull request template.

## 1.0.0 (2026-11-22)

- First release. One command scans a repository: `safe-anything .`
- 72 rules in six families: code (SQL and command injection, XSS, eval, SSRF, path traversal,
  unsafe deserialization, weak crypto, TLS checks off, JWT `none`, template injection, debug
  mode), secrets (provider keys, private keys, passwords, credentials in URLs, `.env` files and examples, a `.gitignore` missing `.env`, secrets behind public
  env prefixes like `NEXT_PUBLIC_`),
  agent setups (skipped permissions, pre-approved shell, unpinned MCP servers, plaintext MCP
  tokens, remote MCP over HTTP, `curl | sh` in hooks and skills, prompt-injection text, credential
  file access, invisible Unicode), mobile (Android manifest, WebView, iOS ATS, tokens in plain
  storage), config (Docker, GitHub Actions, Kubernetes, Terraform, nginx) and dependencies
  (nine lockfile formats checked against OSV.dev, with the nearest fixed version).
- Every finding has a file, a line, a severity, a CWE, an OWASP category, a fix and a link to
  read more. Secrets are redacted in the output.
- Terminal report, `--json`, and `--sarif` for GitHub code scanning; `--severity`, `--fail-on`,
  `--offline`, `--include-tests`, `--list-rules`.
- `safe-anything mcp` serves `scan` and `list_rules` to AI agents over MCP (stdio), with a Claude
  Code plugin and an agent skill.
- A GitHub Action that installs the release binary, scans, and writes SARIF.
- `safe-anything:ignore` silences one line; `.safe-anything-ignore` skips paths.
