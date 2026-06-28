# Luciq PII Masking Linter — design spec (v1)

## Goal
A release gate that automatically catches PII-masking gaps in apps using the Luciq
SDK, across the surfaces the SDK protects — screenshots, Session Replay, and network
logs — so human error (a forgotten mask) cannot reach production. Runs in CI,
deterministic, no developer action required.

## Scope
- **Surfaces:** Visual (screenshots + Session Replay — one surface, same controls),
  Network logs, Defense-in-depth.
- **Platforms:** iOS (Swift) + Android (Kotlin) native first. Flutter, React Native,
  and Web are added later as adapters (see Extensibility).

## Architecture: platform-agnostic core + per-platform adapters
| Core (shared) | Adapter pack (per platform) |
|---|---|
| PII concept families + keyword matching | masking marker APIs, auto-mask call, network toggle |
| candidate → covered → waived → verdict logic | file extensions to scan, manifest/lockfile name |
| compliance dial, severity, waiver parsing | FLAG_SECURE / consent signals, SSUI inflate signals |
| gate behavior + reporting | — |

Adding a platform = adding one entry to the `ADAPTERS` registry, not rebuilding the
core.

## Where the linter gets its information
| Input | Source |
|---|---|
| Masking setup (auto-mask, markers, disable flags, SDK version, consent, FLAG_SECURE) | read from **code** |
| PII concept families + Luciq API names | **built into the linter** |
| Compliance level + custom keywords | **luciq.yml → `pii_masking`** (or `--compliance` / env) |
| Waivers | inline `// luciq-mask-ignore[: reason]` (or `-file` for whole file) |
| Fail-vs-warn | the linter's only switch is `--mode` (default `warn`); **CI** chooses the mode per branch via its own `if:` conditions |

Nothing about the app's real masking config is duplicated in `luciq.yml` — the file
holds only the two things the code cannot express.

## Checks
| ID | Layer | Check | Gate? |
|---|---|---|---|
| `auto-mask-config` | Visual | Auto-mask configured at init, not `MASK_NOTHING` (and `MEDIA` if compliance requires) | hard |
| `unmasked-field` | Visual | Per-view: a field whose name matches a PII keyword (or, under GDPR/HIPAA, any text input) needs a hide tag, auto-mask coverage, or waiver | hard / warn by family |
| `network-disabled` | Network | Auto-masking not explicitly disabled | hard |
| `network-sdk-version` | Network | SDK ≥ 14.2.0 (else not on by default) | hard (warn if version unknown) |
| `consent-gate` | Defense | Consent gates `SessionReplay.enabled` (when compliance requires) | hard |
| `flag-secure` | Defense | No `ignoreFlagSecure(true)` | hard |

### Severity by compliance (non-`unmasked-field` checks)

Severity each check emits per level (`--mode enforce` then decides whether a `fail`
blocks). `—` = the check does not fire at that level. For the `unmasked-field`
per-family matrix see [`docs/keyword-families.md`](keyword-families.md).

| Check | none | soc2 | pci | gdpr | hipaa |
|---|:--:|:--:|:--:|:--:|:--:|
| `auto-mask-config` (absent / `MASK_NOTHING`) | fail | fail | fail | fail | fail |
| `auto-mask-config` (MEDIA required) | — | — | — | — | **fail** |
| card waiver refused | — | — | **fail** | — | — |
| `network-disabled` | fail | fail | fail | fail | fail |
| `network-sdk-version` (< 14.2.0) | fail | fail | fail | fail | fail |
| `network-sdk-version` (unknown) | warn | warn | warn | warn | warn |
| `flag-secure` | fail | fail | fail | fail | fail |
| `consent-gate` | — | — | — | **fail** | **fail** |

Per-level extras: `pci` forbids card waivers; `gdpr` adds the consent gate + the
`input` floor; `hipaa` adds consent gate + `input` floor + required `MEDIA` auto-mask.

Planned next: SSUI `isPrivate` at inflate sites, network payload-body scan
(advisory), server-side custom keys / `usersPageEnabled` (advisory).

## Coverage model (`unmasked-field`)
Per candidate view: **is it a PII candidate?** (a field — input or display label —
whose name matches a built-in/custom keyword) → **is it masked?** (auto-mask covers
its type / inline marker / referenced in `addPrivateViews`/`setPrivateView`) →
**is it waived?** → if none: **fail**. Candidate detection runs on the
comment-stripped source, so a widget or field name that appears only in a comment is
never flagged.

Candidacy is **name-driven** by default: a text input (`TextField`, `EditText`, …) is
flagged only when its name matches a PII keyword family, exactly like a display label —
never merely for being an input. A generically-named input (`TextField("", text:
$value)`) is not a candidate under `none`/`soc2`/`pci`; widen recall there by adding
stems to `pii_masking.keywords`.

**GDPR/HIPAA exception (the `input` floor).** Under `gdpr` and `hipaa`, where masking
all user input is mandatory, the synthetic `input` family kicks in: *every* text input
is a candidate regardless of name (a hard fail unless masked/waived). This floor is
off for the other levels (`Compliance.mask_all_inputs`).

**Waivers.** `// luciq-mask-ignore` waives the field on (or just below) that line;
`// luciq-mask-ignore-file` anywhere in a file waives every candidate in it. A
trailing `: <reason>` is optional and, when present, is surfaced in the finding for
the audit trail. `luciq-ignore` / `luciq-ignore-file` remain as legacy aliases.
Waived card fields are still **refused under PCI** (line- or file-level).

## Output formats & exclusions
`--format` → `text` (default), `xcode` (Run Script inline), `github` (PR
annotations), `sarif` (GitHub Code Scanning / security dashboards; check IDs become
SARIF rule IDs). Skip paths with repeatable `--exclude <glob>` or an `exclude:` list
under `pii_masking` in `luciq.yml`; a pattern matches a whole relative path
(`app/generated/*`) or any single path segment (`Tests`).

## Compliance dial
`compliance:` flips checks between warn and fail and sets required auto-mask types —
the same checks in a different gear. See `docs/keyword-families.md` for the matrix.

## Skill ↔ linter split
- **`luciq_pii_masking_detector`** (skill, separate from `luciq-masking-rules`):
  smart, occasional, run by the privacy owner. Scans the codebase, infers PII
  concepts behind non-obvious field names, and proposes **keyword stems** for
  `pii_masking.keywords`. A human approves and commits.
- **Linter:** dumb, constant, automatic. Reads code + built-ins + the two-key file;
  enforces on every PR / release.

## Honest ceiling
No static gate catches: PII in a generically-named field (`vm.value` holding an SSN),
whether a custom network key is masked server-side, or whether a region visually
renders black at runtime. The last is irreducibly human (the docs' verification step).
The gate raises the floor; it does not replace the pre-production visual check.

## Build phases
1. Config gate (`auto-mask-config`, `network-disabled`, `network-sdk-version`, `consent-gate`, `flag-secure`) — shipped.
2. Coverage gate (`unmasked-field`: keyword + hide-tag + justified waiver) — shipped.
3. Integration & ergonomics (SARIF output, path excludes, fix hints) — shipped.
4. SSUI + advisory (optional AI commenter).
5. Detector skill feeding `keywords:`.
6. More platforms (Flutter / RN / Web adapter packs).
