# opencode config

Global [opencode](https://opencode.ai) configuration, plugins, and package setup synced across machines via git.

## Contents

| Path | Purpose |
|---|---|
| `opencode.json` | Global opencode config (model, provider, MCP, permissions) |
| `plugins/` | Custom opencode plugins (e.g. safety-guard) |
| `package.json` | npm dependencies for plugins |
| `package-lock.json` | Lockfile for reproducible installs |

## New machine bootstrap

```bash
# 1. Clone into ~/.opencode
git clone https://github.com/Khayrulbuet13/opencode.git ~/.opencode

# 2. Install plugin dependencies
cd ~/.opencode && npm install

# 3. Add the API provider credentials (get them from your password manager)
mkdir -p .secrets && chmod 700 .secrets
echo 'sk-YOUR_KEY_HERE' > .secrets/api-provider-key && chmod 600 .secrets/api-provider-key
echo 'BASE_URL' > .secrets/api-provider-baseurl && chmod 600 .secrets/api-provider-baseurl
```

`opencode.json` reads both values from `.secrets/` via `{file:...}` — never committed:
- `apiKey` ← `.secrets/api-provider-key`
- `baseURL` ← `.secrets/api-provider-baseurl`

## Day-to-day sync

```bash
# Push changes
cd ~/.opencode && git add -A && git commit -m "update" && git push

# Pull on another machine
git -C ~/.opencode pull --rebase
```
