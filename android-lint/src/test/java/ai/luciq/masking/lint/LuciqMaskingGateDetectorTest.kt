package ai.luciq.masking.lint

import com.android.tools.lint.checks.infrastructure.TestFiles.gradle
import com.android.tools.lint.checks.infrastructure.TestFiles.kotlin
import com.android.tools.lint.checks.infrastructure.TestLintTask.lint
import com.android.tools.lint.checks.infrastructure.TestMode
import com.android.tools.lint.detector.api.Issue
import org.junit.Test

/**
 * Detector-level tests for [LuciqMaskingGateDetector] — exercising the actual Lint plumbing
 * (UAST per-file handler + whole-project posture pass) rather than just the engine.
 *
 * The central design claim is that the two paths are disjoint: `unmasked-field` comes only
 * from the per-file UAST handler, posture only from the project pass, so nothing is reported
 * twice. These tests pin that by asserting exact occurrence counts.
 *
 * Position-sensitive findings are pinned to [TestMode.DEFAULT]: the engine is line-based, so
 * the harness's source-rewriting modes (extra whitespace, etc.) shift rendered locations
 * without changing *which* fields are flagged — the behavior we care about.
 */
class LuciqMaskingGateDetectorTest {

    private val issues: Array<Issue> = arrayOf(
        LuciqMaskingGateDetector.ISSUE_PII,
        LuciqMaskingGateDetector.ISSUE_PII_ADVISORY,
        LuciqMaskingGateDetector.ISSUE_CONFIG,
        LuciqMaskingGateDetector.ISSUE_CONFIG_ADVISORY,
    )

    // build.gradle with a recent SDK so the network-sdk-version posture check is satisfied.
    private val buildGradle = gradle(
        """
        dependencies {
            implementation("com.luciq.library:luciq:19.8.1")
        }
        """,
    ).indented()

    // A well-configured setup file so posture checks pass and don't drown the assertions.
    private val setup = kotlin(
        """
        package app
        fun setup() {
            Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA)
        }
        """,
    ).indented()

    @Test
    fun `unmasked card field is reported exactly once as an error`() {
        lint().files(
            buildGradle,
            setup,
            kotlin(
                """
                package app
                @Composable fun Pay() {
                    TextField(value = cardNumber, label = { Text("Card Number") })
                }
                """,
            ).indented(),
        )
            .allowMissingSdk()
            .testModes(TestMode.DEFAULT)
            .issues(*issues)
            .run()
            .expectErrorCount(1)
            .expectWarningCount(0)
            .expectContains("[unmasked-field]")
    }

    @Test
    fun `a masked field produces no findings`() {
        lint().files(
            buildGradle,
            setup,
            kotlin(
                """
                package app
                @Composable fun Pay() {
                    TextField(value = cardNumber, modifier = Modifier.luciqPrivate(), label = { Text("Card") })
                }
                """,
            ).indented(),
        )
            .allowMissingSdk()
            .testModes(TestMode.DEFAULT)
            .issues(*issues)
            .run()
            .expectClean()
    }

    @Test
    fun `missing auto-mask posture is reported exactly once`() {
        lint().files(
            buildGradle,
            kotlin(
                """
                package app
                fun setup() { /* no auto-mask configured */ }
                """,
            ).indented(),
        )
            .allowMissingSdk()
            .testModes(TestMode.DEFAULT)
            .issues(*issues)
            .run()
            .expectContains("[auto-mask-config]")
            // posture fires once, not once-per-source-set
            .expectErrorCount(1)
    }
}
