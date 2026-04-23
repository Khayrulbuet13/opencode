/**
 * safety-guard.ts — opencode user-level safety plugin
 *
 * Auto-loaded from ~/.opencode/plugins/ and applies to EVERY project.
 * Enforces safety exclusively via tool.execute.before hooks — the only layer
 * that correctly handles compound commands (&&, ||, ;, |).
 *
 * JSON permission rules are NOT used because they match the entire compound
 * command string as one unit (unpatched bug — see anomalyco/opencode#16180),
 * meaning `git add . && git push` bypasses a "git push*": "deny" rule.
 *
 * Pattern: EXPLAIN-THEN-DEFER
 *   Guards never silently kill an action. They throw a structured, LLM-readable
 *   error that the agent relays verbatim to the user in chat, including what was
 *   attempted, why it was blocked, the likely effect, and safer alternatives.
 *   The user can approve by replying — the agent retries with OPENCODE_SAFETY_OVERRIDE=1.
 *
 * Architecture:
 *   splitCompoundCommand()  — state-machine splitter (not regex); handles quotes, subshells, heredocs
 *   resolvePathSafe()       — path.resolve + realpathSync + startsWith(root + sep) for symlink escapes
 *   10 named guard fns      — each self-contained with JSDoc; return Violation | null
 *   GUARDS registry         — { id, name, fn } array; id matches SAFETY_CONFIG key exactly
 *   runGuard()              — per-guard try/catch (one broken guard cannot disable others)
 *   tool.execute.before     — router: bash → split → all guards; file tools → path guards only
 */

import type { Plugin } from "@opencode-ai/plugin"
import * as path from "path"
import * as fs from "fs"

// ============================================================
// CONFIGURATION
// Toggle individual guards by setting their key to false.
// Keys must exactly match guard id strings in GUARDS below.
// ============================================================

const SAFETY_CONFIG = {
  /** Master kill-switch. Set false to disable all enforcement. */
  enabled: true,
  /** Log every tool call through the router (useful for tuning). */
  debug: false,
  guards: {
    sudo:               true,
    externalPaths:      true,
    dangerousGit:       true,
    dotfileDeletion:    true,
    persistence:        true,
    remoteCodeExec:     true,
    privilegeEscalation: true,
    packagePublish:     true,
    networkBackdoor:    true,
    sensitiveFiles:     true,
  },
} as const

// ============================================================
// TYPES
// ============================================================

interface Violation {
  reason: string
  effect: string
  alternatives: string[]
}

interface Guard {
  id: keyof typeof SAFETY_CONFIG.guards
  name: string
  fn: (segment: string, root: string) => Violation | null
}

// ============================================================
// UTILITY: State-machine compound command splitter
//
// Splits a bash string on &&, ||, ;, | (pipe) while correctly
// skipping operators that appear inside:
//   - Single-quoted strings  'don'"'"'t split here'
//   - Double-quoted strings  "don't split && here"
//   - Backtick subshells     `echo hello`
//   - $(...) subshells       $(echo hello)
//   - Heredoc bodies         <<EOF ... EOF
//   - Backslash escapes      \; \& \|
//
// Using a character-by-character state machine instead of regex
// because regex-based splitting breaks on nested quotes, escaped
// characters, and multi-character operators in the same pass.
// ============================================================

function splitCompoundCommand(cmd: string): string[] {
  const segments: string[] = []
  let current = ""
  let i = 0
  let inSingle = false   // inside '...'
  let inDouble = false   // inside "..."
  let inBacktick = false // inside `...`
  let parenDepth = 0     // nesting depth of $(...)
  let heredocDelim: string | null = null

  while (i < cmd.length) {
    const ch = cmd[i]
    const next = cmd[i + 1]

    // ── Heredoc body: skip until closing delimiter on its own line ──
    if (heredocDelim !== null) {
      const rest = cmd.slice(i)
      // Delimiter must appear at start of a line (after optional leading whitespace for <<-)
      // Escape the delimiter before inserting into RegExp to handle special chars (e.g. END.MARKER)
      const escapedDelim = heredocDelim.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
      const delimRe = new RegExp(`(^|\\n)[ \\t]*${escapedDelim}[ \\t]*(\\n|$)`)
      const match = rest.match(delimRe)
      if (match && match.index !== undefined) {
        const endPos = match.index + match[0].length
        current += rest.slice(0, endPos)
        i += endPos
        heredocDelim = null
        // Closing heredoc line acts as a statement terminator — push this command
        // so that any commands following the heredoc form a new segment.
        if (current.trim()) segments.push(current.trim())
        current = ""
      } else {
        // No closing delimiter found — treat entire remainder as one segment
        current += rest
        i = cmd.length
      }
      continue
    }

    // ── Backslash escape (outside single quotes) ──
    if (ch === "\\" && !inSingle) {
      current += ch
      if (i + 1 < cmd.length) {
        current += cmd[i + 1]
        i += 2
      } else {
        i++
      }
      continue
    }

    // ── Single-quote toggle (no nesting, no escapes inside) ──
    if (ch === "'" && !inDouble && !inBacktick && parenDepth === 0) {
      inSingle = !inSingle
      current += ch
      i++
      continue
    }

    // ── Double-quote toggle ──
    if (ch === '"' && !inSingle && !inBacktick && parenDepth === 0) {
      inDouble = !inDouble
      current += ch
      i++
      continue
    }

    // ── Backtick subshell toggle ──
    if (ch === "`" && !inSingle && !inDouble) {
      inBacktick = !inBacktick
      current += ch
      i++
      continue
    }

    // ── $( subshell open ──
    if (ch === "$" && next === "(" && !inSingle && !inDouble) {
      parenDepth++
      current += ch
      i++
      continue
    }

    // ── ) subshell close ──
    if (ch === ")" && parenDepth > 0 && !inSingle && !inDouble) {
      parenDepth--
      current += ch
      i++
      continue
    }

    // ── Operators and heredoc detection (only when not inside any quote/subshell) ──
    if (!inSingle && !inDouble && !inBacktick && parenDepth === 0) {

      // Heredoc: << or <<-
      if (ch === "<" && next === "<") {
        let k = i + 2
        if (k < cmd.length && cmd[k] === "-") k++ // <<-
        while (k < cmd.length && (cmd[k] === " " || cmd[k] === "\t")) k++ // skip space
        // Delimiter may be quoted: <<"EOF" or <<'EOF'
        let delimQuote = ""
        if (k < cmd.length && (cmd[k] === "'" || cmd[k] === '"')) {
          delimQuote = cmd[k]
          k++
        }
        let delim = ""
        while (k < cmd.length && cmd[k] !== "\n" && cmd[k] !== delimQuote && cmd[k] !== " ") {
          delim += cmd[k]
          k++
        }
        if (delimQuote && k < cmd.length) k++ // closing quote
        current += cmd.slice(i, k)
        i = k
        if (delim) heredocDelim = delim
        continue
      }

      // && operator
      if (ch === "&" && next === "&") {
        if (current.trim()) segments.push(current.trim())
        current = ""
        i += 2
        continue
      }

      // || operator
      if (ch === "|" && next === "|") {
        if (current.trim()) segments.push(current.trim())
        current = ""
        i += 2
        continue
      }

      // | pipe (single — not ||)
      if (ch === "|" && next !== "|") {
        if (current.trim()) segments.push(current.trim())
        current = ""
        i++
        continue
      }

      // ; separator
      if (ch === ";") {
        if (current.trim()) segments.push(current.trim())
        current = ""
        i++
        continue
      }

      // newline as separator
      if (ch === "\n") {
        if (current.trim()) segments.push(current.trim())
        current = ""
        i++
        continue
      }
    }

    current += ch
    i++
  }

  if (current.trim()) segments.push(current.trim())
  // Return empty array for empty/whitespace-only input
  return segments.length > 0 ? segments : (cmd.trim() ? [cmd.trim()] : [])
}

// ============================================================
// UTILITY: Safe path resolution
//
// Three-step sequence that catches all known escape vectors:
//   1. path.resolve(root, p)  — handles relative paths and ../
//   2. fs.realpathSync()      — follows symlinks (catches ln -s /etc /project/evil)
//   3. startsWith(root + sep) — avoids /home/user/projectfoo matching /home/user/project
//
// Returns the canonical absolute path.
// Throws if the resolved path is outside root (and not in an allowed external dir).
// ============================================================

const ALLOWED_EXTERNAL = ["/tmp/", "/var/tmp/", "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"]

function resolvePathSafe(p: string, root: string): { resolved: string; outside: boolean } {
  const expanded = p.replace(/^~/, process.env.HOME ?? "")
  const resolved = path.resolve(root, expanded)
  const safeRoot = root.endsWith(path.sep) ? root : root + path.sep

  // Attempt symlink resolution; fall back to unresolved if path doesn't exist yet
  let real = resolved
  try {
    real = fs.realpathSync(resolved)
  } catch {
    // New/nonexistent file — use resolved path; traversal still checked below
  }

  const isInRoot = real === root || real.startsWith(safeRoot)
  const isAllowedExternal = ALLOWED_EXTERNAL.some(prefix => real.startsWith(prefix))

  return { resolved: real, outside: !isInRoot && !isAllowedExternal }
}

// ============================================================
// UTILITY: Build structured, LLM-readable error message
//
// The error message is formatted so the agent will paste it
// verbatim into the chat, giving the user full context and
// a clear path to override if they choose to.
// ============================================================

function buildExplainError(guardName: string, attempted: string, v: Violation): Error {
  const lines = [
    `SAFETY GUARD TRIGGERED: ${guardName}`,
    ``,
    `Attempted: ${attempted}`,
    `Reason: ${v.reason}`,
    `Likely effect: ${v.effect}`,
    `Safer alternatives:`,
    ...v.alternatives.map(a => `  - ${a}`),
    ``,
    `To proceed: tell me "yes, run it" and I will retry prefixed with OPENCODE_SAFETY_OVERRIDE=1`,
  ]
  return new Error(lines.join("\n"))
}

// ============================================================
// GUARD 1: No sudo / su / doas / pkexec
//
// Blocks privilege escalation via the standard unix mechanisms.
// Running as root or another user bypasses every other guard in
// this file, and can write to any system path.
// ============================================================

function checkNoSudo(seg: string, _root: string): Violation | null {
  // \b before sudo/doas/pkexec, space after to avoid matching "sudoers" etc.
  // su - and su <username> — common forms; bare "su" with no args also blocked
  if (
    /\b(sudo|doas|pkexec)\s/.test(seg) ||
    /\bsu\s+(-|[a-zA-Z])/.test(seg) ||
    /^\s*su\s*$/.test(seg)
  ) {
    return {
      reason: "Running commands as root or another user bypasses all other safety controls",
      effect: "Grants root privileges; can read/write any file, install system software, or modify kernel settings",
      alternatives: [
        "Run the command without sudo if root is not strictly required",
        "You run the command manually in your own terminal",
        "Use a user-level package manager (npm, pip --user, cargo) instead of a system one",
      ],
    }
  }
  return null
}

// ============================================================
// GUARD 2: No external paths
//
// Blocks access to paths outside the project root directory.
// Uses resolvePathSafe() which handles:
//   - Relative traversal: ../../etc/passwd
//   - Home-relative:      ~/sensitive
//   - Symlink escapes:    ln -s /etc /project/evil then access /project/evil
//
// /tmp, /var/tmp, and /dev/* are whitelisted as scratch spaces.
// This guard runs on both bash segments and file-tool paths.
// ============================================================

function checkNoExternalPaths(seg: string, root: string): Violation | null {
  // Extract candidate paths from the segment: absolute paths (/...) or home (~) or parent (..)
  const candidates = seg.match(/(?:(?:^|\s))((?:~|\/)[^\s;|&'"]*|\.\.\/[^\s;|&'"]*)/g)
  if (!candidates) return null

  for (const raw of candidates) {
    const p = raw.trim()
    // Skip flags that look like paths (e.g. --output=/)
    if (p.startsWith("-")) continue

    try {
      const { outside, resolved } = resolvePathSafe(p, root)
      if (outside) {
        return {
          reason: `Path "${p}" resolves to "${resolved}" which is outside the project root`,
          effect: "Reading or writing outside the project can access system files, SSH keys, credentials, or other projects",
          alternatives: [
            "Use a path relative to the project root instead",
            "Tell me explicitly which external path you need and why — I will ask for your approval",
          ],
        }
      }
    } catch {
      // resolvePathSafe failure is non-fatal — skip this candidate
    }
  }
  return null
}

// ============================================================
// GUARD 3: No dangerous git operations
//
// Blocks git commands that are irreversible or push state to remotes.
// Safe read-only commands (status, diff, log, show, blame, branch -l,
// tag -l, remote -v) are explicitly NOT matched.
//
// The --force / -f flag on any git subcommand is also blocked because
// force-push and force-reset can rewrite shared history.
// ============================================================

function checkNoDangerousGit(seg: string, _root: string): Violation | null {
  const dangerous =
    /\bgit\s+(push|commit|reset\s+--hard|clean\s+-[fdxXn]*|rebase(\s+-i)?|config\s+--global|remote\s+remove|tag\s+-d)\b/i
  // --force or -f after git <subcommand> (not in the middle of a filename)
  const forceFlag = /\bgit\s+\w[^|&;]*\s(--force|-f)\b/

  if (dangerous.test(seg) || forceFlag.test(seg)) {
    return {
      reason: "This git operation modifies history, pushes to a remote, or is irreversible",
      effect: "May push unreviewed commits to a shared remote, destroy local history, or rewrite public branches",
      alternatives: [
        "git status / git diff / git log — safe read-only inspection",
        "git push --dry-run origin <branch> — preview without executing",
        "You run the git command manually after reviewing the diff",
      ],
    }
  }
  return null
}

// ============================================================
// GUARD 4: No dotfile/dotdir deletion
//
// Blocks deletion (rm, unlink, rmdir) of any file or directory
// whose final path component starts with a dot.
//
// Dotfiles contain VCS state (.git), credentials (.env, .ssh),
// editor config (.cursor, .opencode, .vscode), and shell config.
// Deleting them is almost never something an AI should do autonomously.
//
// Modifying dotfiles (cat, echo >>, editing content) is NOT blocked —
// that is normal and necessary. Only the rm/unlink family is intercepted.
//
// Universal rule — works in any project because it matches on basename,
// not on project-specific paths.
// ============================================================

function checkNoDotfileDeletion(seg: string, _root: string): Violation | null {
  // Only fire for deletion commands
  if (!/\b(rm|unlink|rmdir)\b/.test(seg)) return null

  // Find arguments that look like dotfiles: .something
  // Match tokens after flags (skip -rf etc.)
  const tokens = seg.split(/\s+/)
  for (const token of tokens) {
    if (token.startsWith("-")) continue // skip flags
    const base = path.basename(token)
    if (base.startsWith(".") && base.length > 1) {
      return {
        reason: `Deletion of dotfile or dotdir "${token}" is blocked`,
        effect: "Deleting dotfiles can destroy VCS history (.git), credentials (.env, .ssh), or editor config (.cursor, .opencode)",
        alternatives: [
          `To clear the contents without deleting: echo -n > ${token}`,
          `To keep a backup: mv ${token} ${token}.bak`,
          "You delete the file manually after confirming you want it gone",
        ],
      }
    }
  }
  return null
}

// ============================================================
// GUARD 5: No persistence mechanisms
//
// Blocks commands that install background processes or modify shell
// startup files. An AI-installed cron job or systemd unit could
// execute arbitrary code on every login or reboot — long after the
// current session ends.
//
// Blocked:
//   - crontab -e, crontab - (piped crontab)
//   - systemctl enable / start / daemon-reload
//   - launchctl load / bootstrap  (macOS)
//   - rc-update add / update-rc.d  (SysV)
//   - Appending to shell rc files (~/.bashrc, ~/.zshrc, ~/.profile, etc.)
//   - Writing to /etc/rc.local or /etc/profile
// ============================================================

function checkNoPersistence(seg: string, _root: string): Violation | null {
  const patterns: RegExp[] = [
    /\bcrontab\s+-e\b/i,                   // crontab -e (opens editor to modify crontab)
    /\bsystemctl\s+(enable|start|daemon-reload)\b/i,
    /\blaunchctl\s+(load|bootstrap)\b/i,
    /\brc-update\s+add\b/i,
    /\bupdate-rc\.d\b/i,
    // Appending to shell startup files (>> redirect)
    />>?\s*~\/\.(bashrc|zshrc|profile|bash_profile|zprofile|kshrc|fishrc|config\/fish\/config\.fish)\b/i,
    // Writing to system-wide startup files
    />>?\s*\/etc\/(rc\.local|profile|environment)\b/i,
  ]

  for (const p of patterns) {
    if (p.test(seg)) {
      return {
        reason: "This command installs a persistent background process or modifies shell startup files",
        effect: "Creates a hook that runs automatically on login or reboot, potentially executing AI-generated code without your presence",
        alternatives: [
          "Describe what you need to run persistently — I will show you the command for you to run manually",
          "Use a project Makefile target or .env file instead of a system cron job",
          "You run the crontab / systemctl command manually after reviewing",
        ],
      }
    }
  }
  return null
}

// ============================================================
// GUARD 6: No remote code execution
//
// Blocks piping network-fetched content directly into a shell
// interpreter. This is the canonical "curl | bash" attack vector:
// even if the URL looks safe, the content can be changed between
// download and inspection, and runs with the user's full privileges.
//
// Blocked:
//   - curl <url> | bash / sh / zsh / python / ruby / perl / node
//   - wget <url> | sh ...
//   - bash <(curl <url>)
//   - curl <url> | base64 -d  (decode-then-exec pattern)
// ============================================================

function checkNoRemoteCodeExec(seg: string, _root: string): Violation | null {
  const patterns: RegExp[] = [
    /(curl|wget)\b[^|]*\|\s*(bash|sh|zsh|ksh|python\d*|ruby|perl|node)\b/i,
    /bash\s+<\s*\(\s*(curl|wget)\b/i,
    /(curl|wget)\b[^|]*\|\s*base64\s+-d/i,
    /fetch\b.*\|\s*(bash|sh)\b/i,
  ]

  for (const p of patterns) {
    if (p.test(seg)) {
      return {
        reason: "Piping network-fetched content directly into a shell interpreter executes untrusted remote code",
        effect: "Runs whatever is at that URL with your user privileges; content can change between download and inspection",
        alternatives: [
          "Download first, inspect, then decide: curl -o install.sh <url> && cat install.sh",
          "Use a package manager (npm, pip, cargo) which provides checksums and a review step",
          "You run the install script manually after reading it",
        ],
      }
    }
  }
  return null
}

// ============================================================
// GUARD 7: No privilege escalation via file permissions
//
// Blocks chmod with world-writable bits (write bit set for "other"
// = last octal digit 2, 3, 6, or 7), chown to root, and setting
// SUID/SGID bits or capabilities.
//
// Also blocks LD_PRELOAD injection which hijacks shared library
// loading for all subsequent processes in the same shell.
//
// Safe examples that are NOT blocked:
//   chmod 755 file   (owner rwx, group/other rx — standard binary)
//   chmod 644 file   (owner rw, group/other r — standard file)
//   chmod +x file    (add execute for owner — common for scripts)
//   chmod g+w file   (group write — deliberate team sharing)
// ============================================================

function checkNoPrivilegeEscalation(seg: string, _root: string): Violation | null {
  const patterns: RegExp[] = [
    // Octal mode: last digit is 2, 3, 6, or 7 (world-writable)
    /\bchmod\s+[0-7]*[2367]\b/,
    // Symbolic: add write for "other" or "all"
    /\bchmod\b[^|&;]*\bo\+[rwxst]*w/i,
    /\bchmod\b[^|&;]*\ba\+[rwxst]*w/i,
    // +w without qualifier means a+w in many shells
    /\bchmod\b[^|&;]*(?<![ugo])\+w\b/,
    // chown to root
    /\bchown\s+root\b/i,
    /\bchown\s+0:/,
    // setuid / setgid / capabilities
    /\b(setuid|setcap|setfacl)\b/i,
    // LD_PRELOAD injection
    /\bLD_PRELOAD\s*=/,
  ]

  for (const p of patterns) {
    if (p.test(seg)) {
      return {
        reason: "This command sets world-writable permissions, grants root ownership, or injects into process loading",
        effect: "Can make files executable as root by any user, or hijack all subsequent processes via shared library injection",
        alternatives: [
          "Use the minimum permission needed (e.g. 755 instead of 777, 644 instead of 666)",
          "Use group ownership instead of chown root",
          "You run this command manually if root access is genuinely required",
        ],
      }
    }
  }
  return null
}

// ============================================================
// GUARD 8: No package publishing
//
// Blocks publishing to public package registries. Publishing is
// effectively irreversible: npm, PyPI, crates.io, and RubyGems
// do not allow true deletion of published versions. An accidental
// publish can expose proprietary code, credentials, or supply-chain
// attack surface.
// ============================================================

function checkNoPackagePublish(seg: string, _root: string): Violation | null {
  const patterns: RegExp[] = [
    // exclude --dry-run which is a safe inspection command
    /\b(npm|yarn|pnpm)\s+publish\b(?!\s*--dry-run)/i,
    /\b(pip|twine)\s+(upload|publish)\b/i,
    /\bcargo\s+publish\b/i,
    /\bgem\s+push\b/i,
    /\bdocker\s+push\b/i,
    /\bwrangler\s+(deploy|publish)\b/i,
    /\bvercel\b[^|&;]*--prod\b/i,
  ]

  for (const p of patterns) {
    if (p.test(seg)) {
      return {
        reason: "Publishing to a public registry is irreversible and immediately publicly downloadable",
        effect: "Package becomes available to all registry users; embedded secrets, wrong version tags, or unreviewed code cannot be fully removed",
        alternatives: [
          "npm pack — build the tarball locally for inspection without publishing",
          "npm publish --dry-run — see exactly what would be included",
          "You run the publish command manually after reviewing the package contents",
        ],
      }
    }
  }
  return null
}

// ============================================================
// GUARD 9: No network backdoors / reverse shells
//
// Blocks commands that open listening network ports or establish
// reverse shell connections. These are primary mechanisms for
// remote access persistence after an initial compromise.
//
// Blocked:
//   - nc -l / ncat -l / netcat -l  (any form of listener flags)
//   - /dev/tcp/ reverse shells      (bash built-in networking)
//   - bash -i >& /dev/tcp/<host>/<port>
//   - socat with LISTEN / TCP-LISTEN
// ============================================================

function checkNoNetworkBackdoor(seg: string, _root: string): Violation | null {
  const patterns: RegExp[] = [
    /\b(nc|ncat|netcat)\b[^|&;]*-[a-zA-Z]*l[a-zA-Z]*/i,  // -l anywhere in flags (e.g. -l, -lvp, -lnp)
    /\/dev\/tcp\//i,
    /bash\s+-i\s*>(&|>)\s*\/dev\/tcp/i,
    /\bsocat\b[^|&;]*(LISTEN|TCP-LISTEN)\b/i,
    /\bpython\d*\s+-c\b[^|&;]*socket[^|&;]*\.listen\b/i,
  ]

  for (const p of patterns) {
    if (p.test(seg)) {
      return {
        reason: "This command opens a network listener or establishes a reverse shell connection",
        effect: "Creates a persistent remote access channel that allows controlling this machine from outside",
        alternatives: [
          "Use ssh for secure remote access with proper key authentication",
          "Bind any local debug server to 127.0.0.1 only, not 0.0.0.0",
          "You run this command manually if a network listener is genuinely needed",
        ],
      }
    }
  }
  return null
}

// ============================================================
// GUARD 10: No sensitive file access
//
// Blocks reading of files that almost exclusively contain credentials
// or private key material. Scope is intentionally narrow to avoid
// false positives on common files.
//
// Blocked: .env (not .env.example/.env.sample), SSH private keys,
//          ~/.aws/credentials, ~/.kube/config, ~/.netrc
//
// NOT blocked: package-lock.json, opencode.json, .gitignore,
//              .eslintrc, .env.example, .ssh/known_hosts, .ssh/config
// ============================================================

function checkNoSensitiveFiles(seg: string, _root: string): Violation | null {
  const patterns: RegExp[] = [
    // .env but not .env.example / .env.sample / .env.template
    // No path anchor — catches 'cat .env', 'cat /path/.env', 'vim .env' etc.
    /\.env(?!\.example|\.sample|\.template|\.test)(\b|$)/i,
    /\bid_rsa\b(?!\.pub)/i,
    /\bid_ed25519\b(?!\.pub)/i,
    /\bid_ecdsa\b(?!\.pub)/i,
    /\bid_dsa\b(?!\.pub)/i,
    // .ssh/ directory contents excluding safe files
    /\.ssh\/(?!(known_hosts|config|authorized_keys))/i,
    /\.aws\/credentials\b/i,
    /\.kube\/config\b/i,
    // .netrc — no \b before \. since . is non-word (word boundary never fires before .)
    /\.netrc\b/i,
  ]

  for (const p of patterns) {
    if (p.test(seg)) {
      return {
        reason: "This path likely contains credentials, tokens, or private key material",
        effect: "Exposing these in chat history, logs, or AI context could leak secrets or allow account takeover",
        alternatives: [
          "Reference environment variables by name in code rather than reading the file",
          "Use a secrets manager (Vault, AWS Secrets Manager, 1Password CLI) for runtime secret access",
          "You read the file manually in your terminal if you need to inspect it",
        ],
      }
    }
  }
  return null
}

// ============================================================
// GUARDS REGISTRY
//
// Order matters: earlier guards fire first on the same segment.
// sudo and externalPaths are first because they are the broadest
// and most dangerous categories.
// ============================================================

// ============================================================
// INTERNAL EXPORTS — for unit testing only
// opencode only uses the SafetyGuard export; these are unused at runtime.
// ============================================================

export {
  splitCompoundCommand,
  resolvePathSafe,
  buildExplainError,
  checkNoSudo,
  checkNoExternalPaths,
  checkNoDangerousGit,
  checkNoDotfileDeletion,
  checkNoPersistence,
  checkNoRemoteCodeExec,
  checkNoPrivilegeEscalation,
  checkNoPackagePublish,
  checkNoNetworkBackdoor,
  checkNoSensitiveFiles,
}

const GUARDS: Guard[] = [
  { id: "sudo",                name: "NoSudo",                fn: checkNoSudo },
  { id: "externalPaths",       name: "NoExternalPaths",       fn: checkNoExternalPaths },
  { id: "dangerousGit",        name: "NoDangerousGit",        fn: checkNoDangerousGit },
  { id: "dotfileDeletion",     name: "NoDotfileDeletion",     fn: checkNoDotfileDeletion },
  { id: "persistence",         name: "NoPersistence",         fn: checkNoPersistence },
  { id: "remoteCodeExec",      name: "NoRemoteCodeExec",      fn: checkNoRemoteCodeExec },
  { id: "privilegeEscalation", name: "NoPrivilegeEscalation", fn: checkNoPrivilegeEscalation },
  { id: "packagePublish",      name: "NoPackagePublish",      fn: checkNoPackagePublish },
  { id: "networkBackdoor",     name: "NoNetworkBackdoor",     fn: checkNoNetworkBackdoor },
  { id: "sensitiveFiles",      name: "NoSensitiveFiles",      fn: checkNoSensitiveFiles },
]

// ============================================================
// PLUGIN EXPORT
// ============================================================

export const SafetyGuard: Plugin = async ({ directory, client }) => {
  const root = directory

  // Filter to enabled guards — key lookup is exact id match (no string mangling)
  const enabledGuards = GUARDS.filter(g => SAFETY_CONFIG.guards[g.id] !== false)

  // ── Structured audit via opencode's official logging API ──
  async function audit(
    level: "info" | "warn" | "error" | "debug",
    guardId: string,
    message: string,
    original: string,
  ): Promise<void> {
    try {
      await client.app.log({
        body: { service: "safety-guard", level, message, extra: { guardId, original } },
      })
    } catch {
      // Never let a logging failure disable safety enforcement
    }
  }

  // ── Per-guard runner with resilience wrapper ──
  // Intentional violations are re-thrown as rich errors (expected control flow).
  // Unexpected exceptions (broken regex, etc.) are logged and skipped so that
  // one malfunctioning guard cannot disable the rest.
  async function runGuard(guard: Guard, segment: string, fullCommand: string): Promise<void> {
    let violation: Violation | null = null
    try {
      violation = guard.fn(segment, root)
    } catch (unexpected) {
      await audit("error", guard.id, `Guard ${guard.name} threw unexpectedly: ${String(unexpected)}`, segment)
      return // resilience: skip this guard, continue with others
    }

    if (violation) {
      await audit("warn", guard.id, violation.reason, fullCommand)
      throw buildExplainError(guard.name, fullCommand, violation)
    }
  }

  return {
    "tool.execute.before": async (input, output) => {
      if (!SAFETY_CONFIG.enabled) return

      // ── Override: user has explicitly approved this specific invocation ──
      // ONLY the visible command-prefix form is accepted: OPENCODE_SAFETY_OVERRIDE=1 git push ...
      // process.env is intentionally NOT checked — an env var set earlier in the shell session
      // would silently bypass all guards with no visibility into what triggered the override.
      const cmd: string = output.args?.command ?? ""
      if (typeof cmd === "string" && cmd.includes("OPENCODE_SAFETY_OVERRIDE=1")) {
        await audit("info", "override", "User-approved safety override", cmd)
        return
      }

      if (SAFETY_CONFIG.debug) {
        await audit("debug", "router", `tool=${input.tool} args=${JSON.stringify(output.args)}`, "")
      }

      // ── BASH: split compound command, run ALL guards on each segment ──
      if (input.tool === "bash") {
        if (!cmd) return
        const segments = splitCompoundCommand(cmd)
        for (const seg of segments) {
          for (const guard of enabledGuards) {
            await runGuard(guard, seg, cmd)
          }
        }
        return
      }

      // ── FILE TOOLS: run path-aware guards only ──
      // dotfileDeletion fires only on bash rm/unlink — file-tool edits are allowed.
      const fileTools = ["read", "write", "edit", "patch"]
      if (fileTools.includes(input.tool)) {
        const filePath: string | undefined =
          output.args?.filePath ??
          output.args?.file_path ??
          output.args?.path
        if (!filePath) return

        const pathGuards = enabledGuards.filter(
          g => g.id === "externalPaths" || g.id === "sensitiveFiles",
        )
        for (const guard of pathGuards) {
          await runGuard(guard, filePath, filePath)
        }
      }
    },
  }
}
