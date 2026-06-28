package ai.luciq.masking.lint

import com.android.tools.lint.client.api.UElementHandler
import com.android.tools.lint.detector.api.Category
import com.android.tools.lint.detector.api.Context
import com.android.tools.lint.detector.api.Detector
import com.android.tools.lint.detector.api.Implementation
import com.android.tools.lint.detector.api.Issue
import com.android.tools.lint.detector.api.JavaContext
import com.android.tools.lint.detector.api.Location
import com.android.tools.lint.detector.api.PartialResult
import com.android.tools.lint.detector.api.Scope
import com.android.tools.lint.detector.api.Severity
import com.android.tools.lint.detector.api.SourceCodeScanner
import org.jetbrains.uast.UElement
import org.jetbrains.uast.UFile
import java.io.File
import java.util.EnumSet

/**
 * The full Luciq PII-masking gate, as an Android Lint check.
 *
 * A single `lintChecks("ai.luciq:luciq-masking-lint:…")` dependency gives an Android team
 * the **complete** gate — compliance dialing, custom `luciq.yml` keywords, the GDPR/HIPAA
 * input floor, and project posture (auto-mask config, network masking, FLAG_SECURE,
 * consent, SDK version) — with no Python required. Both paths run [LuciqMaskingEngine]
 * (the Kotlin port of the Python release gate), so Lint and the CLI stay in lockstep.
 *
 * The check runs in two complementary modes, split by the *nature* of each finding:
 *
 *   1. **Per-field `unmasked-field` — live (as-you-type).** A UAST [UFile] handler runs
 *      [LuciqMaskingEngine.scanFields] on the **in-memory editor buffer**
 *      ([JavaContext.getContents]) for the file being edited, so Android Studio shows the
 *      squiggle while you type — no save or full project pass required. The project-level
 *      input it needs (which families the app auto-masks + `luciq.yml`) is derived once
 *      per project and cached in [fieldContextFor].
 *
 *   2. **Project posture — whole-project (batch).** Auto-mask config, network masking,
 *      FLAG_SECURE, consent and SDK-version checks depend on the *whole* project, so they
 *      can't be live; they run once per project ([reportPosture]) over the files on disk.
 *
 * Splitting this way means the two paths never overlap: fields come only from the UAST
 * handler, posture only from the project pass — no double-reporting under either global
 * or partial (AGP `lintAnalyze*`/`lintReport*`) analysis.
 *
 * Severity → Issue mapping (so `./gradlew lint` blocks CI on hard findings):
 *   - hard fail, unmasked field   → [ISSUE_PII]            (ERROR, blocks)
 *   - soft warn, unmasked field   → [ISSUE_PII_ADVISORY]   (WARNING)
 *   - hard fail, project posture  → [ISSUE_CONFIG]         (ERROR, blocks)
 *   - soft warn, project posture  → [ISSUE_CONFIG_ADVISORY](WARNING)
 *
 * `abortOnError` (Lint's default) means an ERROR finding fails `lint`/`check`/CI; teams
 * can still tune any issue via `android { lint { … } }` or `lint.xml`.
 */
class LuciqMaskingGateDetector : Detector(), SourceCodeScanner {

    // Per-project field-scan context (config + auto-mask posture), cached by config root
    // so we don't re-walk the project for every file the editor analyzes. The detector
    // instance is reused across files within a lint run, so this cache lives for the run.
    private val fieldCtxCache = HashMap<File, LuciqMaskingEngine.FieldScanContext>()

    // ----------------------------------------------------------------------- //
    // Per-field path — live `unmasked-field` findings on the in-memory buffer.
    // ----------------------------------------------------------------------- //
    override fun getApplicableUastTypes(): List<Class<out UElement>> = listOf(UFile::class.java)

    override fun createUastHandler(context: JavaContext): UElementHandler = object : UElementHandler() {
        override fun visitFile(node: UFile) {
            val file = context.file
            val contents = context.getContents()?.toString() ?: return
            val root = findConfigRoot(context.project.dir)
            val ctx = fieldContextFor(context, root)
            val sf = LuciqMaskingEngine.SourceFile(relativize(root, file), file, contents)

            for (f in LuciqMaskingEngine.scanFields(sf, ctx)) {
                if (f.severity == LuciqMaskingEngine.Severity.WAIVED) continue
                val issue = if (f.severity == LuciqMaskingEngine.Severity.FAIL) ISSUE_PII else ISSUE_PII_ADVISORY
                val location = lineLocation(file, contents, f.line)
                context.report(issue, location, "[${f.check}] ${f.message}")
            }
        }
    }

    /** The project's field-scan context, computed once (auto-mask types come from the
     *  setup files on disk, which change rarely) and cached for the run. */
    private fun fieldContextFor(context: JavaContext, root: File): LuciqMaskingEngine.FieldScanContext =
        fieldCtxCache.getOrPut(root) {
            val sources = collectFiles(root).mapNotNull { f ->
                val text = try { if (f.isFile) f.readText() else null } catch (_: Exception) { null }
                    ?: return@mapNotNull null
                LuciqMaskingEngine.SourceFile(relativize(root, f), f, text)
            }
            LuciqMaskingEngine.fieldScanContext(sources, root)
        }

    // ----------------------------------------------------------------------- //
    // Posture path — whole-project config/defense findings, once per project.
    // ----------------------------------------------------------------------- //
    // Lint invokes the project lifecycle differently depending on analysis mode:
    //   • Global analysis (some IDE / standalone runs) → afterCheckRootProject fires once.
    //   • Partial analysis (AGP's `lintAnalyze*` + `lintReport*`, the CI path) → the
    //     per-project callbacks fire once PER SOURCE SET (main/test/androidTest), which
    //     would triple-report. So under partial analysis we only *register* in the
    //     analyze phase and do the single report pass in checkPartialResults (report
    //     phase, called once per project).
    override fun afterCheckRootProject(context: Context) {
        if (context.isGlobalAnalysis()) reportPosture(context)
    }

    override fun afterCheckEachProject(context: Context) {
        if (!context.isGlobalAnalysis()) {
            // Touch partial results so Lint calls checkPartialResults in the report phase.
            context.getPartialResults(ISSUE_CONFIG).map().put(PARTIAL_KEY, true)
        }
    }

    override fun checkPartialResults(context: Context, partialResults: PartialResult) {
        reportPosture(context)
    }

    /** Run the whole-project posture checks once and report each finding exactly once. */
    private fun reportPosture(context: Context) {
        val root = findConfigRoot(context.project.dir)

        val cache = HashMap<File, String?>()
        fun read(f: File): String? = cache.getOrPut(f) {
            try { if (f.isFile) f.readText() else null } catch (_: Exception) { null }
        }

        val sources = collectFiles(root).mapNotNull { f ->
            val text = read(f) ?: return@mapNotNull null
            LuciqMaskingEngine.SourceFile(relativize(root, f), f, text)
        }
        if (sources.isEmpty()) return

        val findings = LuciqMaskingEngine.runPosture(sources, root)
        if (findings.isEmpty()) return

        // Anchor for project-level findings (no specific file): a build script, else any
        // scanned source.
        val anchor = sources.firstOrNull { it.file.name in SDK_FILES }?.file
            ?: sources.first().file

        for (f in findings) {
            if (f.severity == LuciqMaskingEngine.Severity.WAIVED) continue
            val hard = f.severity == LuciqMaskingEngine.Severity.FAIL
            val issue = if (hard) ISSUE_CONFIG else ISSUE_CONFIG_ADVISORY
            val file = f.file ?: anchor
            val contents = read(file)
            val location = lineLocation(file, contents, f.line)
            context.report(issue, location, "[${f.check}] ${f.message}")
        }
    }

    // ----------------------------------------------------------------------- //
    // Filesystem helpers
    // ----------------------------------------------------------------------- //
    /** Nearest ancestor (inclusive) that holds a luciq.yml/luciq.yaml; the module dir
     *  if none is found, so exclude globs resolve against the same root the Python tool
     *  uses (the project that owns the config). */
    private fun findConfigRoot(start: File): File {
        var dir: File? = start.absoluteFile
        while (dir != null) {
            if (File(dir, "luciq.yml").isFile || File(dir, "luciq.yaml").isFile) return dir
            dir = dir.parentFile
        }
        return start.absoluteFile
    }

    private fun collectFiles(root: File): List<File> {
        val out = ArrayList<File>()
        root.walkTopDown()
            .onEnter { it == root || it.name !in SKIP_DIR_PARTS }
            .forEach { f ->
                if (f.isFile && (f.name in SDK_FILES || SOURCE_EXT.any { e -> f.name.endsWith(e) })) {
                    out += f
                }
            }
        return out
    }

    private fun relativize(root: File, file: File): String =
        root.toPath().relativize(file.toPath()).toString().replace(File.separatorChar, '/')

    /** Build a Lint [Location] for a 1-based line (or the whole file when line <= 0). */
    private fun lineLocation(file: File, contents: String?, line: Int): Location {
        if (contents == null || line <= 0) return Location.create(file)
        val lines = contents.split("\n")
        val idx = line - 1
        if (idx !in lines.indices) return Location.create(file)
        var start = 0
        for (i in 0 until idx) start += lines[i].length + 1
        val end = start + lines[idx].length
        return Location.create(file, contents, start, end)
    }

    companion object {
        private const val PARTIAL_KEY = "luciq-gate"
        private val SKIP_DIR_PARTS = setOf("build", "Pods", "node_modules", ".git", "DerivedData", "Carthage")
        private val SOURCE_EXT = setOf(".kt", ".java")
        private val SDK_FILES = setOf("build.gradle", "build.gradle.kts")

        private val IMPL = Implementation(
            LuciqMaskingGateDetector::class.java,
            EnumSet.of(Scope.JAVA_FILE, Scope.TEST_SOURCES),
        )

        private const val PII_EXPLANATION =
            "A text input or label whose name matches a known PII family (card, SSN, " +
                "credentials, email, phone, address, name, DOB, health) is not masked for " +
                "Luciq screenshot / Session Replay capture and has no waiver.\n\n" +
                "Mask it with `Modifier.luciqPrivate()` (Compose) or `luciqPrivate(isPrivate = true)` " +
                "(View), or register it via `Luciq.addPrivateViews(...)`. If it is genuinely not " +
                "sensitive, suppress with a `// luciq-mask-ignore` comment.\n\n" +
                "This check runs the same engine as the standalone `luciq-masking-linter` gate, so " +
                "the full result (compliance dialing, custom luciq.yml keywords, project posture) is " +
                "available from Lint alone."

        private const val CONFIG_EXPLANATION =
            "A project-level Luciq masking posture problem: auto-masking is missing or set to " +
                "MASK_NOTHING, network auto-masking is disabled, FLAG_SECURE is overridden, Session " +
                "Replay is not consent-gated where required, or the Luciq SDK is older than the " +
                "version where network masking is on by default.\n\n" +
                "Fix the masking setup (typically in your Luciq application/setup file) so screenshots, " +
                "Session Replay, and network logs are protected."

        @JvmField
        val ISSUE_PII: Issue = Issue.create(
            id = "LuciqUnmaskedPii",
            briefDescription = "PII field not masked for Luciq capture",
            explanation = PII_EXPLANATION,
            category = Category.SECURITY,
            priority = 8,
            severity = Severity.ERROR,
            implementation = IMPL,
        )

        @JvmField
        val ISSUE_PII_ADVISORY: Issue = Issue.create(
            id = "LuciqUnmaskedPiiAdvisory",
            briefDescription = "PII field not masked for Luciq capture (advisory)",
            explanation = PII_EXPLANATION +
                "\n\nThis finding does not block under the current compliance level; raise the level " +
                "(e.g. gdpr/hipaa) or mask the field to clear it.",
            category = Category.SECURITY,
            priority = 5,
            severity = Severity.WARNING,
            implementation = IMPL,
        )

        @JvmField
        val ISSUE_CONFIG: Issue = Issue.create(
            id = "LuciqMaskingConfig",
            briefDescription = "Luciq masking misconfiguration",
            explanation = CONFIG_EXPLANATION,
            category = Category.SECURITY,
            priority = 8,
            severity = Severity.ERROR,
            implementation = IMPL,
        )

        @JvmField
        val ISSUE_CONFIG_ADVISORY: Issue = Issue.create(
            id = "LuciqMaskingConfigAdvisory",
            briefDescription = "Luciq masking posture advisory",
            explanation = CONFIG_EXPLANATION +
                "\n\nThis advisory does not block; verify the masking posture manually.",
            category = Category.SECURITY,
            priority = 5,
            severity = Severity.WARNING,
            implementation = IMPL,
        )

        val ALL_ISSUES: List<Issue> = listOf(ISSUE_PII, ISSUE_PII_ADVISORY, ISSUE_CONFIG, ISSUE_CONFIG_ADVISORY)
    }
}
