#!/usr/bin/env python3
"""Luciq PII Masking Linter.

A release gate that statically checks a Luciq-SDK app for PII-masking gaps across
the surfaces the SDK protects: screenshots / Session Replay (visual), network logs,
and defense-in-depth controls.

Design notes:
- Reads the masking SETUP directly from the code (auto-mask config, private-view
  markers, network toggle, SDK version, FLAG_SECURE, consent). Nothing about the
  app's real configuration is duplicated in a config file.
- Ships its own PII concept families (see FAMILIES). These are documented for humans
  in docs/keyword-families.md, but that file is NOT read by the linter.
- The ONLY things it can't learn from code come from luciq.yml's `pii_masking`
  section: the compliance level and custom keyword families. Compliance can also be
  supplied via --compliance or the LUCIQ_COMPLIANCE env var (which override the file).
- Platform support is an adapter registry (ADAPTERS). Adding Flutter / RN / Web later
  means adding one entry, not touching the core. iOS + Android native ship first.

Zero third-party dependencies (stdlib only).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------- #
# PII concept families (built-in). Documented in docs/keyword-families.md.
# Each family maps to a case-insensitive regex matched against identifier names.
# Order matters: the first family that matches a line wins, so the more specific /
# higher-risk families come first and the noisy "name" family comes last.
# --------------------------------------------------------------------------- #
FAMILY_ORDER = [
    "card", "ssn", "credentials", "health", "dob",
    "email", "phone", "address", "name",
]

BUILTIN_FAMILIES = {
    "card":        r"card(?:num|number|holder)?|\bpan\b|cvv|cvc|ccnum|\biban\b|account.?number|routing",
    "ssn":         r"\bssn\b|social.?security|national.?id|tax.?id|fiscal",
    "credentials": r"password|passwd|\bpwd\b|\bpin\b|\botp\b|secret|api.?key|auth.?token|access.?token|bearer",
    "health":      r"diagnos|\bmrn\b|icd.?\d|medication|prescription|\bpatient\b",
    "dob":         r"\bdob\b|birth.?date|date.?of.?birth|birthday",
    "email":       r"e-?mail",
    "phone":       r"phone|msisdn|mobile.?(?:num|number)|telephone",
    "address":     r"home.?address|street|postal|zip.?code|postcode|billing.?address|shipping.?address",
    "name":        r"(?:first|last|full|patient|holder|display)_?name|fullname",
}


@dataclass
class Compliance:
    name: str
    hard_families: set
    require_media: bool = False
    consent_required: bool = False
    forbid_card_waiver: bool = False
    # When True, EVERY text input is a candidate regardless of its name (the synthetic
    # "input" family). Only GDPR/HIPAA, where masking all user input is mandatory,
    # turn this on; for none/soc2/pci candidacy is purely name-driven.
    mask_all_inputs: bool = False


_ALL = set(FAMILY_ORDER) | {"input"}

COMPLIANCE_PRESETS = {
    "none":  Compliance("none",  {"card", "ssn", "credentials"}),
    "soc2":  Compliance("soc2",  {"card", "ssn", "credentials"}),
    "pci":   Compliance("pci",   {"card", "ssn", "credentials"}, forbid_card_waiver=True),
    "gdpr":  Compliance("gdpr",  {"email", "phone", "name", "address", "dob",
                                  "ssn", "card", "credentials", "input"},
                        consent_required=True, mask_all_inputs=True),
    "hipaa": Compliance("hipaa", _ALL, require_media=True, consent_required=True,
                        mask_all_inputs=True),
}

# --------------------------------------------------------------------------- #
# Platform adapters. Add a new platform = add a dict entry here.
# --------------------------------------------------------------------------- #
ADAPTERS = {
    "ios": {
        "extensions": (".swift",),
        # Real Luciq iOS API (19.x): Luciq.setAutoMaskScreenshots([...]). The older
        # autoMaskScreenshotOptions / *Types spellings are kept for back-compat.
        "auto_mask_call": (r"setAutoMaskScreenshots", r"autoMaskScreenshotOptions",
                           r"setAutoMaskScreenshotsTypes"),
        "mask_nothing": (r"maskNothing", r"MASK_NOTHING"),
        # SwiftUI: .luciq_privateView()  •  UIKit: view.luciq_privateView = true
        # (.luciqPrivate / .ibgPrivate are legacy spellings, kept for back-compat.)
        "markers_inline": (r"\.luciq_privateView\b", r"\.luciqPrivate\(",
                           r"\.ibgPrivate\s*=\s*true"),
        "markers_ref": (r"addPrivateViews\s*\(", r"setPrivateView\s*\("),
        "input_types": (r"\bSecureField\b", r"\bTextField\b", r"\bUITextField\b", r"\bUITextView\b"),
        "text_contexts": (r"\bText\s*\(", r"\bLabel\s*\(", r"\.text\s*="),
        "network_disable": (r"NetworkLogger\.autoMaskingEnabled\s*=\s*false",
                            r"IBGNetworkLogger\.autoMaskingEnabled\s*=\s*false"),
        "sdk_files": ("Podfile.lock", "Package.resolved"),
        "fix_hint": ("mask it: `.luciq_privateView()` (SwiftUI) or "
                     "`view.luciq_privateView = true` (UIKit), or pass it to "
                     "`addPrivateViews(...)`; or waive with `// luciq-mask-ignore`"),
    },
    "android": {
        "extensions": (".kt", ".java"),
        "auto_mask_call": (r"setAutoMaskScreenshotsTypes",),
        "mask_nothing": (r"MASK_NOTHING",),
        "markers_inline": (r"Modifier\.luciqPrivate\(", r"luciqPrivate\(\s*isPrivate\s*=\s*true"),
        "markers_ref": (r"addPrivateViews\s*\(", r"setPrivateView\s*\("),
        "input_types": (r"\bEditText\b", r"\bTextInputEditText\b", r"\bTextField\b"),
        "text_contexts": (r"\bText\s*\(", r"\bTextView\b", r"\.text\s*="),
        "flag_secure": (r"ignoreFlagSecure\s*\(\s*true\s*\)",),
        "network_disable": (r"setNetworkAutoMaskingState\s*\(\s*Feature\.State\.DISABLED",),
        "sdk_files": ("build.gradle", "build.gradle.kts"),
        "fix_hint": ("mask it: `Modifier.luciqPrivate()` (Compose) or "
                     "`luciqPrivate(isPrivate = true)`, or pass it to "
                     "`addPrivateViews(...)`; or waive with `// luciq-mask-ignore`"),
    },
}

MASK_TYPE_TOKENS = {
    "TEXT_INPUTS": r"TEXT_INPUTS|\.textInputs\b",
    "LABELS":      r"LABELS|\.labels\b",
    "MEDIA":       r"MEDIA|\.media\b",
    "WEB_VIEWS":   r"WEB_VIEWS|\.webViews\b",
}

# Waiver markers (live in comments). The preferred spelling is `luciq-mask-ignore`;
# `luciq-ignore` is kept as a legacy alias. A trailing `: <reason>` is optional and,
# when present, is surfaced in the finding for the audit trail.
#   line-level:  // luciq-mask-ignore[: reason]   -> waives the next/this candidate
#   file-level:  // luciq-mask-ignore-file        -> waives every candidate in the file
FILE_WAIVER_RE = re.compile(r"luciq(?:-mask)?-ignore-file\b", re.I)
LINE_WAIVER_RE = re.compile(
    r"luciq(?:-mask)?-ignore\b(?!-file)[ \t]*:?[ \t]*(?P<reason>[^\n]*)", re.I)


def line_waiver(line: str) -> Optional[str]:
    """Return the reason for a line-level waiver ("" if the marker is bare), or None
    if no line-level waiver marker is present on the line."""
    m = LINE_WAIVER_RE.search(line)
    if not m:
        return None
    return m.group("reason").strip()
SKIP_DIR_PARTS = {"build", "Pods", "node_modules", ".git", "DerivedData", "Carthage"}


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    check: str          # e.g. "unmasked-field"
    severity: str       # "fail" | "warn"
    file: str
    line: int
    family: str
    message: str

    def render(self, root: str) -> str:
        rel = os.path.relpath(self.file, root) if self.file else "(project)"
        loc = f"{rel}:{self.line}" if self.line else rel
        tag = "FAIL" if self.severity == "fail" else "warn"
        return f"  [{tag}] {self.check} {loc} — {self.message}"


@dataclass
class Result:
    findings: list = field(default_factory=list)
    compliance: str = "none"
    mode: str = "warn"
    platforms: list = field(default_factory=list)
    exit_code: int = 0


# --------------------------------------------------------------------------- #
# Minimal YAML reader (stdlib-only fallback). Uses pyyaml if available.
# Supports the subset luciq.yml needs: nested maps, scalars, inline [a, b] lists,
# and block "- item" lists.
# --------------------------------------------------------------------------- #
def _load_yaml(text: str) -> dict:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except Exception:
        return _mini_yaml(text)


def _mini_yaml(text: str) -> dict:
    root: dict = {}
    stack = [(-1, root)]  # (indent, container)
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if val == "":
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        elif val.startswith("[") and val.endswith("]"):
            items = [v.strip().strip("'\"") for v in val[1:-1].split(",") if v.strip()]
            parent[key] = items
        else:
            parent[key] = val.strip("'\"")
    return root


def load_config(project: str) -> dict:
    path = os.path.join(project, "luciq.yml")
    if not os.path.isfile(path):
        path = os.path.join(project, "luciq.yaml")
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        data = _load_yaml(fh.read())
    section = (data or {}).get("pii_masking", {}) or {}
    return section if isinstance(section, dict) else {}


# --------------------------------------------------------------------------- #
# Scanning helpers
# --------------------------------------------------------------------------- #
def _excluded(rel: str, patterns: list) -> bool:
    """Match a project-relative path against user exclude globs. A pattern matches
    if it globs the whole relative path (e.g. `app/generated/*`) or equals any single
    path segment (e.g. `Tests` excludes every directory named Tests)."""
    rel = rel.replace(os.sep, "/")
    segs = rel.split("/")
    for p in patterns:
        p = str(p).replace(os.sep, "/").rstrip("/")
        if not p:
            continue
        if p in segs or fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/*"):
            return True
    return False


def iter_source_files(project: str, excludes: Optional[list] = None):
    excludes = list(excludes or [])
    for dirpath, dirnames, filenames in os.walk(project):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIR_PARTS
            and not _excluded(os.path.relpath(os.path.join(dirpath, d), project), excludes)
        ]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if _excluded(os.path.relpath(full, project), excludes):
                continue
            yield full


def platform_for(path: str) -> Optional[str]:
    for name, ad in ADAPTERS.items():
        if path.endswith(ad["extensions"]):
            return name
    return None


def _any(patterns, text) -> bool:
    return any(re.search(p, text) for p in patterns)


_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def strip_comments(text: str) -> str:
    """Blank out // line comments and /* */ block comments while preserving line
    count and column positions (comment chars become spaces), so a commented-out
    masking marker / API call is not mistaken for real, active masking.

    Naive on purpose: it does not parse string literals, but Luciq masking markers
    and config calls never live inside strings, so this is safe for our patterns.
    """
    text = _BLOCK_COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    return _LINE_COMMENT_RE.sub("", text)


_STEM_SEP_RE = re.compile(r"[\s_\-./]+")
_STEM_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+")


def stem_to_regex(word: str) -> str:
    """Turn a custom keyword stem into a regex that matches the same word however its
    parts are separated. The stem is split into words on explicit separators
    (`_ - . /` / whitespace) and on camelCase humps, each word is escaped, and the
    words are rejoined with an optional separator — mirroring the built-in families'
    `.?` joins. So one stem `membershipNo` also matches `membership_no`,
    `membership-no`, and `membership no`; a single-word stem is unaffected."""
    parts: list[str] = []
    for chunk in _STEM_SEP_RE.split(str(word)):
        if chunk:
            parts.extend(_STEM_WORD_RE.findall(chunk) or [chunk])
    if not parts:
        return re.escape(str(word))
    return r"[\s_\-./]?".join(re.escape(p) for p in parts)


def compile_families(custom_keywords: dict) -> list:
    """Return [(family, compiled_regex)] = built-ins plus custom keyword stems."""
    merged: dict[str, list[str]] = {f: [BUILTIN_FAMILIES[f]] for f in FAMILY_ORDER}
    order = list(FAMILY_ORDER)
    for fam, words in (custom_keywords or {}).items():
        if isinstance(words, str):
            words = [words]
        stems = [stem_to_regex(w) for w in (words or [])]
        if not stems:
            continue
        merged.setdefault(fam, [])
        merged[fam].extend(stems)
        if fam not in order:
            order.insert(0, fam)  # custom families are checked first
    return [(fam, re.compile("|".join(merged[fam]), re.I)) for fam in order]


# --------------------------------------------------------------------------- #
# Project-level facts (config posture, read from code)
# --------------------------------------------------------------------------- #
@dataclass
class ProjectFacts:
    platforms: set = field(default_factory=set)
    auto_mask_configured: bool = False
    auto_mask_nothing: bool = False
    auto_mask_types: set = field(default_factory=set)
    network_disabled_at: Optional[tuple] = None
    flag_secure_at: Optional[tuple] = None
    consent_unguarded: bool = False
    sdk_version: Optional[tuple] = None
    sdk_version_str: Optional[str] = None


def gather_facts(project: str, files: list) -> ProjectFacts:
    facts = ProjectFacts()
    sdk_filenames = {fn for ad in ADAPTERS.values() for fn in ad["sdk_files"]}
    for path in files:
        base = os.path.basename(path)
        plat = platform_for(path)

        # Manifest / lockfiles carry the SDK version but are not source files,
        # so handle them by filename independently of the platform extension.
        if base in sdk_filenames and facts.sdk_version is None:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    mtext = fh.read()
                m = re.search(r"(?:luciq|instabug)[^0-9\n]{0,60}?(\d+)\.(\d+)\.(\d+)",
                              mtext, re.I)
                if m:
                    facts.sdk_version = tuple(int(g) for g in m.groups())
                    facts.sdk_version_str = ".".join(m.groups())
            except OSError:
                pass

        if not plat:
            continue
        facts.platforms.add(plat)
        ad = ADAPTERS[plat]
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                raw_text = fh.read()
        except OSError:
            continue
        # Strip comments so commented-out config / markers don't count as active.
        text = strip_comments(raw_text)
        lines = text.splitlines(keepends=True)

        if _any(ad["auto_mask_call"], text):
            facts.auto_mask_configured = True
            # capture configured types in a window around the call
            for i, ln in enumerate(lines):
                if _any(ad["auto_mask_call"], ln):
                    window = "".join(lines[i:i + 4])
                    for tok, rx in MASK_TYPE_TOKENS.items():
                        if re.search(rx, window):
                            facts.auto_mask_types.add(tok)
        if _any(ad["mask_nothing"], text):
            facts.auto_mask_nothing = True

        for i, ln in enumerate(lines, 1):
            if _any(ad["network_disable"], ln) and facts.network_disabled_at is None:
                facts.network_disabled_at = (path, i)
            if "flag_secure" in ad and _any(ad["flag_secure"], ln) and facts.flag_secure_at is None:
                facts.flag_secure_at = (path, i)

        if re.search(r"SessionReplay\.enabled\s*=\s*true", text) and not re.search(r"consent", text, re.I):
            facts.consent_unguarded = True
    return facts


# --------------------------------------------------------------------------- #
# Per-file visual scan (unmasked-field: per-view coverage)
# --------------------------------------------------------------------------- #
def scan_visual(path: str, plat: str, families: list, facts: ProjectFacts,
                comp: Compliance) -> list:
    ad = ADAPTERS[plat]
    findings: list[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return findings
    # Comment-stripped view of the file (line numbers preserved) for detecting
    # ACTIVE masking markers. Commented-out markers must not count as coverage.
    code_lines = strip_comments("".join(lines)).splitlines(keepends=True)
    code_text = "".join(code_lines)

    # identifiers passed to addPrivateViews(...) / setPrivateView(...) anywhere in file
    privatized: set[str] = set()
    for rx in ad["markers_ref"]:
        for m in re.finditer(rx + r"([^)]*)", code_text):
            for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", m.group(1)):
                privatized.add(tok)

    hint = ad.get("fix_hint", "")
    # A file-level waiver marker anywhere in the file waives every candidate in it.
    file_waived = bool(FILE_WAIVER_RE.search("".join(lines)))
    for idx, raw in enumerate(lines):
        # Detect candidate fields on the comment-stripped line so a field name or
        # widget mentioned only in a trailing/line comment is never a candidate.
        code = code_lines[idx] if idx < len(code_lines) else ""
        is_input = _any(ad["input_types"], code)
        is_text = _any(ad["text_contexts"], code)
        if not (is_input or is_text):
            continue

        family = None
        for fam, rx in families:
            if rx.search(code):
                family = fam
                break
        if family is None:
            # No PII keyword on the field name. Candidacy is name-driven by default:
            # a TextField/EditText is flagged only when its name matches a (built-in
            # or custom) keyword family, never merely for being an input. The sole
            # exception is GDPR/HIPAA (comp.mask_all_inputs), where masking all user
            # input is mandatory, so an unnamed input is still a candidate ("input").
            if is_input and comp.mask_all_inputs:
                family = "input"
            else:
                continue

        # ---- coverage tests ----
        # The waiver itself lives in a comment, so read it from the RAW lines.
        reason = line_waiver(raw)
        if reason is None and idx > 0:
            reason = line_waiver(lines[idx - 1])
        inline = _any(ad["markers_inline"], "".join(code_lines[idx:idx + 3]))
        ref = any(tok in privatized for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code))
        auto = ((is_input and "TEXT_INPUTS" in facts.auto_mask_types) or
                (is_text and "LABELS" in facts.auto_mask_types))

        if inline or ref or auto:
            continue
        if reason is not None or file_waived:
            # waived; a card-data waiver is still refused under PCI (resolved later
            # via the severity pass). Surface the reason/scope for the audit trail.
            if reason:
                note = f"waived inline: {reason}"
            elif reason is not None:
                note = "waived inline"
            else:
                note = "waived (file-level luciq-mask-ignore-file)"
            findings.append(Finding("unmasked-field", "waived", path, idx + 1, family,
                                    f"{family} field is {note}"))
            continue

        msg = (f"{family} field is not masked (no private marker, "
               f"not covered by auto-mask, no waiver)")
        if hint:
            msg += f". To fix: {hint}"
        findings.append(Finding("unmasked-field", "fail", path, idx + 1, family, msg))
    return findings


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def resolve_compliance(cli_value, config) -> Compliance:
    raw = (cli_value or os.environ.get("LUCIQ_COMPLIANCE")
           or config.get("compliance") or "none")
    return COMPLIANCE_PRESETS.get(str(raw).strip().lower(), COMPLIANCE_PRESETS["none"])


def apply_severity(findings: list, comp: Compliance) -> list:
    out = []
    for f in findings:
        if f.severity == "waived":
            if comp.forbid_card_waiver and f.family == "card":
                out.append(Finding(f.check, "fail", f.file, f.line, f.family,
                                   f"{f.family} waiver is not allowed under {comp.name.upper()}"))
            continue  # accepted waiver → drop
        if f.check == "unmasked-field":
            f.severity = "fail" if f.family in comp.hard_families else "warn"
        out.append(f)
    return out


def _merge_excludes(config, cli_excludes) -> list:
    cfg = config.get("exclude", []) or []
    if isinstance(cfg, str):
        cfg = [cfg]
    return [str(x) for x in cfg] + list(cli_excludes or [])


def run(project: str, cli_compliance=None, mode="warn", excludes=None) -> Result:
    project = os.path.abspath(project)
    config = load_config(project)
    comp = resolve_compliance(cli_compliance, config)
    families = compile_families(config.get("keywords", {}))
    excludes = _merge_excludes(config, excludes)

    files = list(iter_source_files(project, excludes))
    facts = gather_facts(project, files)
    findings: list[Finding] = []

    # ---- config / posture checks ----
    if facts.platforms:
        if facts.auto_mask_nothing:
            findings.append(Finding("auto-mask-config", "fail", "", 0, "config",
                                    "auto-mask is set to MASK_NOTHING (screenshots unmasked)"))
        elif not facts.auto_mask_configured:
            findings.append(Finding("auto-mask-config", "fail", "", 0, "config",
                                    "no auto-mask configured (setAutoMaskScreenshotsTypes / "
                                    "autoMaskScreenshotOptions absent)"))
        elif comp.require_media and "MEDIA" not in facts.auto_mask_types:
            findings.append(Finding("auto-mask-config", "fail", "", 0, "config",
                                    f"{comp.name.upper()} requires MEDIA in auto-mask types; "
                                    f"configured: {sorted(facts.auto_mask_types) or 'none'}"))

    if facts.network_disabled_at:
        p, ln = facts.network_disabled_at
        findings.append(Finding("network-disabled", "fail", p, ln, "network",
                                "network auto-masking is explicitly DISABLED"))
    if facts.sdk_version and facts.sdk_version < (14, 2, 0):
        findings.append(Finding("network-sdk-version", "fail", "", 0, "network",
                                f"SDK {facts.sdk_version_str} < 14.2.0 — network auto-masking "
                                "is not on by default; upgrade or enable explicitly"))
    elif facts.sdk_version is None and facts.platforms:
        findings.append(Finding("network-sdk-version", "warn", "", 0, "network",
                                "could not determine Luciq SDK version — verify it is ≥ 14.2.0"))
    if facts.flag_secure_at:
        p, ln = facts.flag_secure_at
        findings.append(Finding("flag-secure", "fail", p, ln, "defense",
                                "ignoreFlagSecure(true) overrides FLAG_SECURE — secure windows "
                                "will be captured"))
    if comp.consent_required and facts.consent_unguarded:
        findings.append(Finding("consent-gate", "fail", "", 0, "defense",
                                f"{comp.name.upper()} requires consent gating; "
                                "SessionReplay.enabled = true is not guarded by a consent check"))

    # ---- visual per-view checks ----
    for path in files:
        plat = platform_for(path)
        if plat:
            findings.extend(scan_visual(path, plat, families, facts, comp))

    findings = apply_severity(findings, comp)

    result = Result(findings=findings, compliance=comp.name, mode=mode,
                    platforms=sorted(facts.platforms))
    hard = any(f.severity == "fail" for f in findings)
    result.exit_code = 1 if (mode == "enforce" and hard) else 0
    return result


def _ide_level(f: Finding, mode: str) -> str:
    # red (blocks) only when it would actually block; otherwise yellow.
    return "error" if (f.severity == "fail" and mode == "enforce") else "warning"


def format_xcode(result: Result, root: str) -> str:
    """Xcode parses `file:line:col: warning|error: msg` from a Run Script phase."""
    lines = []
    for f in result.findings:
        level = _ide_level(f, result.mode)
        if f.file:
            lines.append(f"{os.path.abspath(f.file)}:{f.line}:1: {level}: "
                         f"[{f.check}] {f.message}")
        else:
            lines.append(f"{level}: [{f.check}] {f.message}")
    return "\n".join(lines)


def format_github(result: Result, root: str) -> str:
    """GitHub Actions workflow-command annotations (inline on the PR diff)."""
    lines = []
    for f in result.findings:
        level = _ide_level(f, result.mode)
        if f.file:
            rel = os.path.relpath(f.file, root)
            lines.append(f"::{level} file={rel},line={f.line}::[{f.check}] {f.message}")
        else:
            lines.append(f"::{level}::[{f.check}] {f.message}")
    return "\n".join(lines)


def format_sarif(result: Result, root: str) -> str:
    """SARIF 2.1.0 — ingestible by GitHub Code Scanning and most security dashboards.
    Each check ID becomes a SARIF rule; findings without a file are run-level."""
    rule_ids = sorted({f.check for f in result.findings})
    rules = [{"id": rid, "name": rid,
              "shortDescription": {"text": rid.replace("-", " ")}} for rid in rule_ids]
    sarif_results = []
    for f in result.findings:
        entry = {
            "ruleId": f.check,
            "level": _ide_level(f, result.mode),
            "message": {"text": f.message},
            "properties": {"family": f.family, "severity": f.severity},
        }
        if f.file:
            rel = os.path.relpath(f.file, root).replace(os.sep, "/")
            entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {"startLine": max(f.line, 1)},
                }
            }]
        sarif_results.append(entry)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Luciq PII Masking Linter",
                                "informationUri": "https://luciq.ai",
                                "rules": rules}},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2)


def format_report(result: Result, root: str) -> str:
    fails = [f for f in result.findings if f.severity == "fail"]
    warns = [f for f in result.findings if f.severity == "warn"]
    out = []
    out.append("Luciq PII Masking Linter")
    out.append(f"  platforms : {', '.join(result.platforms) or 'none detected'}")
    out.append(f"  compliance: {result.compliance}    mode: {result.mode}")
    out.append("")
    if not result.findings:
        out.append("  No masking gaps found. ✓")
    else:
        for f in sorted(result.findings, key=lambda x: (x.severity != "fail", x.check)):
            out.append(f.render(root))
    out.append("")
    out.append(f"Summary: {len(fails)} fail, {len(warns)} warn")
    verdict = "BLOCK release" if result.exit_code else (
        "pass (warn mode — would block on release branch)" if fails else "pass")
    out.append(f"Verdict: {verdict}")
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Luciq PII Masking Linter (iOS + Android).")
    p.add_argument("path", nargs="?", default=".",
                   help="project root to scan (default: current directory)")
    p.add_argument("--compliance", help="override compliance level (none/soc2/pci/gdpr/hipaa)")
    p.add_argument("--mode", choices=["enforce", "warn"], default="warn",
                   help="enforce blocks the build on failures; warn reports only "
                        "(default: warn). CI decides which mode to run per branch.")
    p.add_argument("--format", choices=["text", "xcode", "github", "sarif"], default="text",
                   help="text (default), xcode (inline in Xcode via a Run Script "
                        "phase), github (PR annotations), or sarif (GitHub Code "
                        "Scanning / security dashboards)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="path glob or directory name to skip (repeatable); merged "
                        "with `exclude:` in luciq.yml. e.g. --exclude 'app/generated/*' "
                        "--exclude Tests")
    args = p.parse_args(argv)

    result = run(args.path, cli_compliance=args.compliance, mode=args.mode,
                 excludes=args.exclude)
    root = os.path.abspath(args.path)
    renderer = {"xcode": format_xcode, "github": format_github,
                "sarif": format_sarif}.get(args.format, format_report)
    out = renderer(result, root)
    if out:
        print(out)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
