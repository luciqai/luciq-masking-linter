# Luciq PII Masking Linter

Catches **unmasked PII** — card numbers, SSNs, emails, passwords — in your **Luciq-SDK**
app before it ships, across screenshots, Session Replay, and network logs. Use it in your
editor, in CI, or as a release gate.

Works for **iOS** (Swift) and **Android** (Kotlin/Java).

**Install for:** [Android](#android) · [iOS](#ios)  — each covers local + CI.

---

## Install

### Android

Native Android Lint, distributed via **JitPack** — no Python needed.

**1.** Add JitPack to `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }   // ← add this
    }
}
```

**2.** Add the check to `app/build.gradle.kts`:

```kotlin
dependencies {
    lintChecks("com.github.luciqai:luciq-masking-linter:0.1.1")
}
```

> Note the artifact id is `luciq-masking-linter` (the repo name) — JitPack publishes under
> the repo name, not the module's `luciq-masking-lint` id.

**3.** Run it:

```bash
./gradlew :app:lint
```

Unmasked PII is now a **red Lint error** — a squiggle in Android Studio as you type, and a
failed build in CI. It reads your project's [`luciq.yml`](#configure--luciqyml-optional)
(compliance level + custom keywords) — the same file the CLI uses. Control blocking vs.
report-only in [Lint settings](#android--lint-settings).

> On Maven Central instead? Use `ai.luciq:luciq-masking-lint:0.1.1` and drop the JitPack line.

### iOS

Install the command-line tool (Python 3.8+, no other dependencies). Use **pipx** so the
command lands in `~/.local/bin` — a stable location the Xcode build can find:

```bash
pipx install luciq-masking-linter
```

To see findings **inline in Xcode**, add a Run Script build phase. Xcode build phases run
with a minimal `PATH`, so add `~/.local/bin` before calling the command — otherwise the
build reports it as "not installed" even when it is:

```bash
export PATH="$HOME/.local/bin:$PATH"
luciq-masking-linter "$SRCROOT" --format xcode --mode warn
```

### CI / other

Install the tool, then run it where you want a gate. GitHub Actions:

```yaml
- uses: actions/setup-python@v5
- run: pip install luciq-masking-linter
- run: luciq-masking-linter . --mode enforce      # fails the job on a gap
```

Any CI works the same: install, then `luciq-masking-linter . --mode enforce`.

- Inline PR annotations: `--format github` · GitHub Code Scanning: `--format sarif`.
- **Android CI** can skip Python and just run `./gradlew :app:lint`.

---

## Tuning the linter

How you control the linter — blocking vs. report-only, output format, what to skip — depends
on your platform, but the goal is the same. Jump to yours:

- **iOS / CI** → [command-line flags](#ios--ci--command-line-flags)
- **Android** → [Lint settings](#android--lint-settings)

Compliance level and `exclude` always come from [`luciq.yml`](#configure--luciqyml-optional) —
shared by both platforms.

### iOS / CI — command-line flags

The `luciq-masking-linter` command takes a path to scan plus a few flags.

```bash
luciq-masking-linter [path] --mode enforce --compliance gdpr --format sarif
```

| Flag | Default | What it does |
|---|---|---|
| `--mode` | `warn` | `warn` reports and exits `0`; `enforce` exits `1` on a blocking gap (the gate) |
| `--compliance` | from `luciq.yml` | `none` / `soc2` / `pci` / `gdpr` / `hipaa` — overrides the file |
| `--format` | `text` | `text`, `xcode` (inline in Xcode), `github` (PR annotations), `sarif` (Code Scanning) |
| `--exclude` | — | a path or glob to skip (repeatable) |

A run looks like:

```
[FAIL] unmasked-field PaymentView.swift:24 — card field is not masked …
[warn] unmasked-field ProfileView.swift:31 — phone field is not masked …
Summary: 1 fail, 1 warn   →   BLOCK release
```

### Android — Lint settings

Out of the box the check **blocks**: `./gradlew :app:lint` (and CI) fail on a masking gap.
You tune it in `app/build.gradle.kts`, inside `android { lint { … } }`.

**Most common: show findings as warnings only (squiggles, but never fail the build).**

```kotlin
android {
    lint {
        warning += "LuciqUnmaskedPii"     // demote the two blocking checks…
        warning += "LuciqMaskingConfig"   // …to non-blocking warnings
    }
}
```

That's it — you still get the editor squiggles and report entries, but the build stays
green.

Other knobs, same `lint { }` block:

| Want to… | Add this |
|---|---|
| turn a check off completely | `disable += "LuciqUnmaskedPii"` |
| keep errors but don't fail the build (project-wide) | `abortOnError = false` |
| block only *new* findings | `baseline = file("lint-baseline.xml")` |
| write SARIF for GitHub Code Scanning | `sarifReport = true` |

**The four issue ids** (use them in `warning +=` / `disable +=` above):

| Issue id | Default | What it covers |
|---|---|---|
| `LuciqUnmaskedPii` | **error** (blocks) | an unmasked PII field |
| `LuciqMaskingConfig` | **error** (blocks) | project posture: auto-mask, network, `FLAG_SECURE`, consent, old SDK |
| `LuciqUnmaskedPiiAdvisory` | warning | advisory field finding |
| `LuciqMaskingConfigAdvisory` | warning | advisory posture finding |

---

## Skip a finding

If a flagged field isn't really PII, skip it with a comment:

- `// luciq-mask-ignore` on the field's line (or the line just above it).
- `// luciq-mask-ignore-file` anywhere in a file to skip that whole file.
- Add a reason for the audit trail: `// luciq-mask-ignore: masked upstream`.

*Card fields can't be skipped under `pci`.*

---

## Configure — `luciq.yml` (optional)

Put one file at your project root. It holds the handful of things the linter can't read
from your code. **Both** the CLI and the Android Lint check read it.

```yaml
pii_masking:
  compliance: gdpr               # none | soc2 | pci | gdpr | hipaa
  keywords:                      # your app-specific PII field names
    account: [loyaltyId, membershipNo]
  exclude: [app/generated]       # paths to skip
```

### Compliance levels — what blocks vs. warns

| Level | Blocks on |
|---|---|
| `none` / `soc2` | card, SSN, credentials |
| `pci` | same, **and** card waivers are refused |
| `gdpr` | + email, phone, name, address, DOB, **every** text input; consent required |
| `hipaa` | all of the above + health; MEDIA auto-mask + consent required |

---

## Exit codes

`0` = clean, or `--mode warn`. `1` = `--mode enforce` **and** a blocking gap.

On Android, `./gradlew :app:lint` fails the build on a blocking gap the same way — unless
`abortOnError = false`.
