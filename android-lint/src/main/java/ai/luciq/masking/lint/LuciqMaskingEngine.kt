package ai.luciq.masking.lint

import java.io.File

/**
 * Pure-Kotlin port of the standalone Python release gate (`luciq_masking_linter.py`),
 * Android adapter only. This is the **single brain** behind the Android Lint check: it
 * mirrors the Python engine's families, compliance dialing, project-posture facts,
 * per-view visual scan, and severity resolution so an Android team can run the *full*
 * gate from Lint alone — no Python on the machine or in CI.
 *
 * Faithful map to `luciq_masking_linter.py`:
 *   - [BUILTIN_FAMILIES] / [FAMILY_ORDER]      ← BUILTIN_FAMILIES / FAMILY_ORDER
 *   - [COMPLIANCE_PRESETS]                      ← COMPLIANCE_PRESETS
 *   - [ADAPTER]                                 ← ADAPTERS["android"]
 *   - [gatherFacts]                             ← gather_facts
 *   - [scanVisual]                              ← scan_visual
 *   - [run] (posture + severity)                ← run / apply_severity
 *
 * The Python tool stays the cross-platform source of truth (it also does iOS); when its
 * Android families/markers change, update this file in lockstep. See android-lint/README.
 */
object LuciqMaskingEngine {

    // ----------------------------------------------------------------------- //
    // PII concept families (built-in). Ported verbatim from BUILTIN_FAMILIES.
    // ----------------------------------------------------------------------- //
    val FAMILY_ORDER: List<String> = listOf(
        "card", "ssn", "credentials", "health", "dob",
        "email", "phone", "address", "name",
    )

    private val BUILTIN_FAMILIES: Map<String, String> = mapOf(
        "card" to """card(?:num|number|holder)?|\bpan\b|cvv|cvc|ccnum|\biban\b|account.?number|routing""",
        "ssn" to """\bssn\b|social.?security|national.?id|tax.?id|fiscal""",
        "credentials" to """password|passwd|\bpwd\b|\bpin\b|\botp\b|secret|api.?key|auth.?token|access.?token|bearer""",
        "health" to """diagnos|\bmrn\b|icd.?\d|medication|prescription|\bpatient\b""",
        "dob" to """\bdob\b|birth.?date|date.?of.?birth|birthday""",
        "email" to """e-?mail""",
        "phone" to """phone|msisdn|mobile.?(?:num|number)|telephone""",
        "address" to """home.?address|street|postal|zip.?code|postcode|billing.?address|shipping.?address""",
        "name" to """(?:first|last|full|patient|holder|display)_?name|fullname""",
    )

    // ----------------------------------------------------------------------- //
    // Compliance presets. Ported from COMPLIANCE_PRESETS.
    // ----------------------------------------------------------------------- //
    data class Compliance(
        val name: String,
        val hardFamilies: Set<String>,
        val requireMedia: Boolean = false,
        val consentRequired: Boolean = false,
        val forbidCardWaiver: Boolean = false,
        val maskAllInputs: Boolean = false,
    )

    private val ALL_FAMILIES: Set<String> = FAMILY_ORDER.toSet() + "input"

    val COMPLIANCE_PRESETS: Map<String, Compliance> = mapOf(
        "none" to Compliance("none", setOf("card", "ssn", "credentials")),
        "soc2" to Compliance("soc2", setOf("card", "ssn", "credentials")),
        "pci" to Compliance("pci", setOf("card", "ssn", "credentials"), forbidCardWaiver = true),
        "gdpr" to Compliance(
            "gdpr",
            setOf("email", "phone", "name", "address", "dob", "ssn", "card", "credentials", "input"),
            consentRequired = true, maskAllInputs = true,
        ),
        "hipaa" to Compliance(
            "hipaa", ALL_FAMILIES,
            requireMedia = true, consentRequired = true, maskAllInputs = true,
        ),
    )

    // ----------------------------------------------------------------------- //
    // Android adapter. Ported from ADAPTERS["android"].
    // ----------------------------------------------------------------------- //
    private val AUTO_MASK_CALL = listOf("""setAutoMaskScreenshotsTypes""")
    private val MASK_NOTHING = listOf("""MASK_NOTHING""")
    private val MARKERS_INLINE = listOf(
        """Modifier\.luciqPrivate\(""",
        """luciqPrivate\(\s*isPrivate\s*=\s*true""",
    )
    private val MARKERS_REF = listOf("""addPrivateViews\s*\(""", """setPrivateView\s*\(""")
    private val INPUT_TYPES = listOf("""\bEditText\b""", """\bTextInputEditText\b""", """\bTextField\b""")
    private val TEXT_CONTEXTS = listOf("""\bText\s*\(""", """\bTextView\b""", """\.text\s*=""")
    private val FLAG_SECURE = listOf("""ignoreFlagSecure\s*\(\s*true\s*\)""")
    private val NETWORK_DISABLE = listOf("""setNetworkAutoMaskingState\s*\(\s*Feature\.State\.DISABLED""")
    private val SDK_FILES = setOf("build.gradle", "build.gradle.kts")
    private const val FIX_HINT =
        "mask it: `Modifier.luciqPrivate()` (Compose) or `luciqPrivate(isPrivate = true)`, " +
            "or pass it to `addPrivateViews(...)`; or waive with `// luciq-mask-ignore`"

    private val MASK_TYPE_TOKENS: Map<String, String> = mapOf(
        "TEXT_INPUTS" to """TEXT_INPUTS|\.textInputs\b""",
        "LABELS" to """LABELS|\.labels\b""",
        "MEDIA" to """MEDIA|\.media\b""",
        "WEB_VIEWS" to """WEB_VIEWS|\.webViews\b""",
    )

    private const val MIN_NETWORK_SDK = "14.2.0"

    // Waiver markers (live in comments). Ported from FILE_WAIVER_RE / LINE_WAIVER_RE.
    private val FILE_WAIVER_RE = Regex("""luciq(?:-mask)?-ignore-file\b""", RegexOption.IGNORE_CASE)
    private val LINE_WAIVER_RE =
        Regex("""luciq(?:-mask)?-ignore\b(?!-file)[ \t]*:?[ \t]*(?<reason>[^\n]*)""", RegexOption.IGNORE_CASE)

    private val SKIP_DIR_PARTS = setOf("build", "Pods", "node_modules", ".git", "DerivedData", "Carthage")
    private val SOURCE_EXT = setOf(".kt", ".java")

    // ----------------------------------------------------------------------- //
    // Findings
    // ----------------------------------------------------------------------- //
    enum class Severity { FAIL, WARN, WAIVED }

    data class Finding(
        val check: String,
        val severity: Severity,
        val file: File?,
        val line: Int,
        val family: String,
        val message: String,
    )

    /** A source file handed to the engine: its path relative to the scan root, the
     *  absolute [File] (for Lint locations), and its text. */
    data class SourceFile(val rel: String, val file: File, val text: String)

    // ----------------------------------------------------------------------- //
    // Config (luciq.yml) — only what the engine can't read from code.
    // ----------------------------------------------------------------------- //
    data class Config(
        val compliance: String?,
        val keywords: Map<String, List<String>>,
        val exclude: List<String>,
    )

    fun loadConfig(root: File): Config {
        val file = listOf("luciq.yml", "luciq.yaml")
            .map { File(root, it) }
            .firstOrNull { it.isFile }
            ?: return Config(null, emptyMap(), emptyList())
        val section = miniYaml(file.readText())["pii_masking"] as? Map<*, *> ?: return Config(null, emptyMap(), emptyList())

        val compliance = section["compliance"] as? String
        val keywords = LinkedHashMap<String, List<String>>()
        (section["keywords"] as? Map<*, *>)?.forEach { (k, v) ->
            val fam = k?.toString() ?: return@forEach
            keywords[fam] = when (v) {
                is List<*> -> v.map { it.toString() }
                is String -> listOf(v)
                else -> emptyList()
            }
        }
        val exclude = when (val e = section["exclude"]) {
            is List<*> -> e.map { it.toString() }
            is String -> listOf(e)
            else -> emptyList()
        }
        return Config(compliance, keywords, exclude)
    }

    // ----------------------------------------------------------------------- //
    // Public entry point
    // ----------------------------------------------------------------------- //
    /**
     * Run the full Android gate over [sources] rooted at [root] (the directory that
     * holds luciq.yml — paths in `exclude:` are relative to it). [complianceOverride]
     * (e.g. from the LUCIQ_COMPLIANCE env var) beats the file.
     */
    fun run(sources: List<SourceFile>, root: File, complianceOverride: String? = null): List<Finding> {
        val p = prepare(sources, root, complianceOverride)
        val findings = postureFindings(p.facts, p.comp)
        // ---- per-view visual checks ----
        for (sf in p.files) {
            if (isSource(sf.file)) findings += scanVisual(sf, p.families, p.facts.autoMaskTypes, p.comp)
        }
        return applySeverity(findings, p.comp)
    }

    /**
     * Project-level posture/config findings only (no per-field visual scan), severity
     * applied. This is what the **whole-project** Lint detector reports; the per-field
     * `unmasked-field` findings come from the **per-file** path ([fieldScanContext] +
     * [scanFields]) so the two never double-report.
     */
    fun runPosture(sources: List<SourceFile>, root: File, complianceOverride: String? = null): List<Finding> {
        val p = prepare(sources, root, complianceOverride)
        return applySeverity(postureFindings(p.facts, p.comp), p.comp)
    }

    /**
     * Everything [scanFields] needs that isn't the file itself — derived once per project
     * and cheap to cache. The only whole-project input the per-field scan depends on is
     * [autoMaskTypes] (which masking families the app auto-masks); [families] and [comp]
     * are pure luciq.yml config. Holding these here lets a per-file (UAST) detector scan
     * the in-memory editor buffer live while reusing the exact same matching engine as the
     * batch gate.
     */
    data class FieldScanContext(
        val families: List<Pair<String, Regex>>,
        val comp: Compliance,
        val autoMaskTypes: Set<String>,
        val exclude: List<String>,
    )

    /** Build a [FieldScanContext] from a project scan (config + auto-mask posture). */
    fun fieldScanContext(sources: List<SourceFile>, root: File, complianceOverride: String? = null): FieldScanContext {
        val p = prepare(sources, root, complianceOverride)
        return FieldScanContext(p.families, p.comp, p.facts.autoMaskTypes, p.exclude)
    }

    /**
     * Scan a single [sf] for `unmasked-field` findings, severity applied. A pure function
     * of the file's text plus the project [ctx], so it is safe to run on an in-memory
     * editor buffer for live (as-you-type) highlighting. Honors luciq.yml `exclude:` the
     * same way the batch path does, using [SourceFile.rel].
     */
    fun scanFields(sf: SourceFile, ctx: FieldScanContext): List<Finding> {
        if (!isSource(sf.file) || excluded(sf.rel, ctx.exclude)) return emptyList()
        return applySeverity(scanVisual(sf, ctx.families, ctx.autoMaskTypes, ctx.comp), ctx.comp)
    }

    /** Reusable per-project state derived once from [sources] + luciq.yml. */
    private class Prepared(
        val files: List<SourceFile>,
        val families: List<Pair<String, Regex>>,
        val comp: Compliance,
        val facts: Facts,
        val exclude: List<String>,
    )

    private fun prepare(sources: List<SourceFile>, root: File, complianceOverride: String?): Prepared {
        val config = loadConfig(root)
        val comp = resolveCompliance(complianceOverride, config)
        val families = compileFamilies(config.keywords)
        val files = sources.filterNot { excluded(it.rel, config.exclude) }
        val facts = gatherFacts(files)
        return Prepared(files, families, comp, facts, config.exclude)
    }

    /** ← run / apply_severity (posture half). Project-level config & defense checks. */
    private fun postureFindings(facts: Facts, comp: Compliance): MutableList<Finding> {
        val findings = ArrayList<Finding>()

        // ---- config / posture checks (only if we actually scanned Android source) ----
        if (facts.hasPlatform) {
            if (facts.autoMaskNothing) {
                findings += Finding(
                    "auto-mask-config", Severity.FAIL, null, 0, "config",
                    "auto-mask is set to MASK_NOTHING (screenshots unmasked)",
                )
            } else if (!facts.autoMaskConfigured) {
                findings += Finding(
                    "auto-mask-config", Severity.FAIL, null, 0, "config",
                    "no auto-mask configured (setAutoMaskScreenshotsTypes absent)",
                )
            } else if (comp.requireMedia && "MEDIA" !in facts.autoMaskTypes) {
                findings += Finding(
                    "auto-mask-config", Severity.FAIL, null, 0, "config",
                    "${comp.name.uppercase()} requires MEDIA in auto-mask types; " +
                        "configured: ${facts.autoMaskTypes.sorted().ifEmpty { listOf("none") }}",
                )
            }
        }

        facts.networkDisabledAt?.let { (f, ln) ->
            findings += Finding("network-disabled", Severity.FAIL, f, ln, "network",
                "network auto-masking is explicitly DISABLED")
        }
        if (facts.sdkVersion != null && compareVersions(facts.sdkVersion!!, MIN_NETWORK_SDK) < 0) {
            findings += Finding("network-sdk-version", Severity.FAIL, null, 0, "network",
                "SDK ${facts.sdkVersionStr} < $MIN_NETWORK_SDK — network auto-masking is not on " +
                    "by default; upgrade or enable explicitly")
        } else if (facts.sdkVersion == null && facts.hasPlatform) {
            findings += Finding("network-sdk-version", Severity.WARN, null, 0, "network",
                "could not determine Luciq SDK version — verify it is >= $MIN_NETWORK_SDK")
        }
        facts.flagSecureAt?.let { (f, ln) ->
            findings += Finding("flag-secure", Severity.FAIL, f, ln, "defense",
                "ignoreFlagSecure(true) overrides FLAG_SECURE — secure windows will be captured")
        }
        if (comp.consentRequired && facts.consentUnguarded) {
            findings += Finding("consent-gate", Severity.FAIL, null, 0, "defense",
                "${comp.name.uppercase()} requires consent gating; SessionReplay.enabled = true " +
                    "is not guarded by a consent check")
        }

        return findings
    }

    // ----------------------------------------------------------------------- //
    // Project-level facts (config posture, read from code). ← gather_facts
    // ----------------------------------------------------------------------- //
    private class Facts {
        var hasPlatform = false
        var autoMaskConfigured = false
        var autoMaskNothing = false
        val autoMaskTypes = HashSet<String>()
        var networkDisabledAt: Pair<File, Int>? = null
        var flagSecureAt: Pair<File, Int>? = null
        var consentUnguarded = false
        var sdkVersion: String? = null
        var sdkVersionStr: String? = null
    }

    private val SDK_VERSION_RE =
        Regex("""(?:luciq|instabug)[^0-9\n]{0,60}?(\d+)\.(\d+)\.(\d+)""", RegexOption.IGNORE_CASE)
    private val SESSION_REPLAY_ENABLED_RE = Regex("""SessionReplay\.enabled\s*=\s*true""")
    private val CONSENT_RE = Regex("""consent""", RegexOption.IGNORE_CASE)
    private val IDENT_RE = Regex("""[A-Za-z_][A-Za-z0-9_]*""")

    private fun gatherFacts(files: List<SourceFile>): Facts {
        val facts = Facts()
        for (sf in files) {
            val base = sf.file.name

            if (base in SDK_FILES && facts.sdkVersion == null) {
                SDK_VERSION_RE.find(sf.text)?.let { m ->
                    facts.sdkVersion = "${m.groupValues[1]}.${m.groupValues[2]}.${m.groupValues[3]}"
                    facts.sdkVersionStr = facts.sdkVersion
                }
            }

            if (!isSource(sf.file)) continue
            facts.hasPlatform = true

            // Strip comments so commented-out config / markers don't count as active.
            val text = stripComments(sf.text)
            val lines = text.split("\n")

            if (anyMatch(AUTO_MASK_CALL, text)) {
                facts.autoMaskConfigured = true
                for (i in lines.indices) {
                    if (anyMatch(AUTO_MASK_CALL, lines[i])) {
                        val window = lines.subList(i, minOf(i + 4, lines.size)).joinToString("\n")
                        for ((tok, rx) in MASK_TYPE_TOKENS) {
                            if (Regex(rx).containsMatchIn(window)) facts.autoMaskTypes.add(tok)
                        }
                    }
                }
            }
            if (anyMatch(MASK_NOTHING, text)) facts.autoMaskNothing = true

            for ((i, ln) in lines.withIndex()) {
                if (anyMatch(NETWORK_DISABLE, ln) && facts.networkDisabledAt == null) {
                    facts.networkDisabledAt = sf.file to (i + 1)
                }
                if (anyMatch(FLAG_SECURE, ln) && facts.flagSecureAt == null) {
                    facts.flagSecureAt = sf.file to (i + 1)
                }
            }

            if (SESSION_REPLAY_ENABLED_RE.containsMatchIn(text) && !CONSENT_RE.containsMatchIn(text)) {
                facts.consentUnguarded = true
            }
        }
        return facts
    }

    // ----------------------------------------------------------------------- //
    // Per-file visual scan (unmasked-field). ← scan_visual
    // ----------------------------------------------------------------------- //
    private fun scanVisual(
        sf: SourceFile,
        families: List<Pair<String, Regex>>,
        autoMaskTypes: Set<String>,
        comp: Compliance,
    ): List<Finding> {
        val findings = ArrayList<Finding>()
        val lines = sf.text.split("\n")
        val codeLines = stripComments(sf.text).split("\n")
        val codeText = codeLines.joinToString("\n")

        // identifiers passed to addPrivateViews(...) / setPrivateView(...) anywhere in file
        val privatized = HashSet<String>()
        for (rx in MARKERS_REF) {
            for (m in Regex(rx + "([^)]*)").findAll(codeText)) {
                for (tok in IDENT_RE.findAll(m.groupValues[1])) privatized.add(tok.value)
            }
        }

        val fileWaived = FILE_WAIVER_RE.containsMatchIn(sf.text)
        for (idx in lines.indices) {
            val code = codeLines.getOrElse(idx) { "" }
            val isInput = anyMatch(INPUT_TYPES, code)
            val isText = anyMatch(TEXT_CONTEXTS, code)
            if (!(isInput || isText)) continue

            var family: String? = null
            for ((fam, rx) in families) {
                if (rx.containsMatchIn(code)) { family = fam; break }
            }
            if (family == null) {
                family = if (isInput && comp.maskAllInputs) "input" else continue
            }

            // ---- coverage tests ----
            val reason = lineWaiver(lines[idx]) ?: if (idx > 0) lineWaiver(lines[idx - 1]) else null
            val window = codeLines.subList(idx, minOf(idx + 3, codeLines.size)).joinToString("\n")
            val inline = anyMatch(MARKERS_INLINE, window)
            val toks = IDENT_RE.findAll(code).map { it.value }.toList()
            val ref = toks.any { it in privatized }
            val auto = (isInput && "TEXT_INPUTS" in autoMaskTypes) ||
                (isText && "LABELS" in autoMaskTypes)

            if (inline || ref || auto) continue
            if (reason != null || fileWaived) {
                val note = when {
                    !reason.isNullOrEmpty() -> "waived inline: $reason"
                    reason != null -> "waived inline"
                    else -> "waived (file-level luciq-mask-ignore-file)"
                }
                findings += Finding("unmasked-field", Severity.WAIVED, sf.file, idx + 1, family,
                    "$family field is $note")
                continue
            }

            findings += Finding(
                "unmasked-field", Severity.FAIL, sf.file, idx + 1, family,
                "$family field is not masked (no private marker, not covered by auto-mask, " +
                    "no waiver). To fix: $FIX_HINT",
            )
        }
        return findings
    }

    // ----------------------------------------------------------------------- //
    // Severity resolution. ← apply_severity
    // ----------------------------------------------------------------------- //
    private fun applySeverity(findings: List<Finding>, comp: Compliance): List<Finding> {
        val out = ArrayList<Finding>()
        for (f in findings) {
            if (f.severity == Severity.WAIVED) {
                if (comp.forbidCardWaiver && f.family == "card") {
                    out += f.copy(
                        severity = Severity.FAIL,
                        message = "${f.family} waiver is not allowed under ${comp.name.uppercase()}",
                    )
                }
                continue // accepted waiver → drop
            }
            if (f.check == "unmasked-field") {
                out += f.copy(severity = if (f.family in comp.hardFamilies) Severity.FAIL else Severity.WARN)
            } else {
                out += f
            }
        }
        return out
    }

    // ----------------------------------------------------------------------- //
    // Helpers
    // ----------------------------------------------------------------------- //
    private fun resolveCompliance(override: String?, config: Config): Compliance {
        val raw = override
            ?: System.getenv("LUCIQ_COMPLIANCE")
            ?: config.compliance
            ?: "none"
        return COMPLIANCE_PRESETS[raw.trim().lowercase()] ?: COMPLIANCE_PRESETS.getValue("none")
    }

    private fun compileFamilies(custom: Map<String, List<String>>): List<Pair<String, Regex>> {
        val merged = LinkedHashMap<String, MutableList<String>>()
        for (f in FAMILY_ORDER) merged[f] = mutableListOf(BUILTIN_FAMILIES.getValue(f))
        val order = FAMILY_ORDER.toMutableList()
        for ((fam, words) in custom) {
            val stems = words.map { stemToRegex(it) }.filter { it.isNotEmpty() }
            if (stems.isEmpty()) continue
            merged.getOrPut(fam) { mutableListOf() }.addAll(stems)
            if (fam !in order) order.add(0, fam) // custom families are checked first
        }
        return order.map { it to Regex(merged.getValue(it).joinToString("|"), RegexOption.IGNORE_CASE) }
    }

    private val STEM_SEP_RE = Regex("""[\s_\-./]+""")
    private val STEM_WORD_RE = Regex("""[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+""")

    /** ← stem_to_regex: match the same word however its parts are separated. */
    private fun stemToRegex(word: String): String {
        val parts = ArrayList<String>()
        for (chunk in STEM_SEP_RE.split(word)) {
            if (chunk.isEmpty()) continue
            val words = STEM_WORD_RE.findAll(chunk).map { it.value }.toList()
            if (words.isEmpty()) parts.add(chunk) else parts.addAll(words)
        }
        if (parts.isEmpty()) return Regex.escape(word)
        return parts.joinToString("""[\s_\-./]?""") { Regex.escape(it) }
    }

    private fun lineWaiver(line: String): String? {
        val m = LINE_WAIVER_RE.find(line) ?: return null
        return (m.groups["reason"]?.value ?: "").trim()
    }

    private val BLOCK_COMMENT_RE = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
    private val LINE_COMMENT_RE = Regex("""//[^\n]*""")
    private val NON_NEWLINE_RE = Regex("""[^\n]""")

    /** ← strip_comments: blank out comments while preserving line/column positions. */
    private fun stripComments(text: String): String {
        val noBlock = BLOCK_COMMENT_RE.replace(text) { m -> NON_NEWLINE_RE.replace(m.value, " ") }
        return LINE_COMMENT_RE.replace(noBlock, "")
    }

    private fun anyMatch(patterns: List<String>, text: String): Boolean =
        patterns.any { Regex(it).containsMatchIn(text) }

    private fun isSource(file: File): Boolean = SOURCE_EXT.any { file.name.endsWith(it) }

    /** ← _excluded: match a project-relative path against user exclude globs. */
    private fun excluded(rel: String, patterns: List<String>): Boolean {
        val r = rel.replace(File.separatorChar, '/')
        val segs = r.split("/")
        for (p0 in patterns) {
            val p = p0.replace(File.separatorChar, '/').trimEnd('/')
            if (p.isEmpty()) continue
            if (p in segs || globMatch(r, p) || globMatch(r, "$p/*")) return true
        }
        return false
    }

    private fun globMatch(s: String, pat: String): Boolean {
        val sb = StringBuilder("^")
        for (c in pat) {
            when (c) {
                '*' -> sb.append(".*")
                '?' -> sb.append('.')
                '.', '(', ')', '+', '|', '^', '$', '{', '}', '\\' -> sb.append('\\').append(c)
                else -> sb.append(c)
            }
        }
        sb.append('$')
        return Regex(sb.toString()).matches(s)
    }

    private fun compareVersions(a: String, b: String): Int {
        val pa = a.split(".").map { it.toIntOrNull() ?: 0 }
        val pb = b.split(".").map { it.toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val x = pa.getOrElse(i) { 0 }
            val y = pb.getOrElse(i) { 0 }
            if (x != y) return x.compareTo(y)
        }
        return 0
    }

    /** ← _mini_yaml: the small subset luciq.yml needs (nested maps, scalars, inline lists). */
    private fun miniYaml(text: String): Map<String, Any> {
        val root = LinkedHashMap<String, Any>()
        val stack = ArrayDeque<Pair<Int, MutableMap<String, Any>>>()
        stack.addLast(-1 to root)
        for (raw in text.split("\n")) {
            if (raw.isBlank() || raw.trimStart().startsWith("#")) continue
            val indent = raw.length - raw.trimStart(' ').length
            val line = raw.trim()
            while (stack.size > 1 && indent <= stack.last().first) stack.removeLast()
            val parent = stack.last().second
            if (!line.contains(":")) continue
            val key = line.substringBefore(":").trim()
            val value = line.substringAfter(":").trim()
            when {
                value.isEmpty() -> {
                    val child = LinkedHashMap<String, Any>()
                    parent[key] = child
                    stack.addLast(indent to child)
                }
                value.startsWith("[") && value.endsWith("]") -> {
                    parent[key] = value.substring(1, value.length - 1)
                        .split(",")
                        .map { it.trim().trim('\'', '"') }
                        .filter { it.isNotEmpty() }
                }
                else -> parent[key] = value.trim('\'', '"')
            }
        }
        return root
    }
}
