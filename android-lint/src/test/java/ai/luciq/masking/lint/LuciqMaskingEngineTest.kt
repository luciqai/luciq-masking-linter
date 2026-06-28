package ai.luciq.masking.lint

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * Unit tests for [LuciqMaskingEngine] — the Kotlin port of the Python release gate.
 *
 * Most tests are hermetic (synthetic sources written to a temp dir). The final test is a
 * parity check against the real SampleAppAndroid when it is checked out next to this repo;
 * it asserts the same fail/warn counts the Python tool produces, and is skipped otherwise.
 */
class LuciqMaskingEngineTest {

    private fun tempRoot(vararg files: Pair<String, String>): File {
        val root = Files.createTempDirectory("luciq-engine-test").toFile()
        for ((rel, content) in files) {
            val f = File(root, rel)
            f.parentFile.mkdirs()
            f.writeText(content)
        }
        return root
    }

    private fun runEngine(root: File, compliance: String? = null): List<LuciqMaskingEngine.Finding> {
        val sources = root.walkTopDown()
            .filter { it.isFile }
            .map { LuciqMaskingEngine.SourceFile(it.relativeTo(root).path, it, it.readText()) }
            .toList()
        return LuciqMaskingEngine.run(sources, root, compliance)
    }

    private fun fails(fs: List<LuciqMaskingEngine.Finding>) = fs.count { it.severity == LuciqMaskingEngine.Severity.FAIL }
    private fun warns(fs: List<LuciqMaskingEngine.Finding>) = fs.count { it.severity == LuciqMaskingEngine.Severity.WARN }

    @Test
    fun `card field unmasked is a hard fail at none`() {
        val root = tempRoot(
            "app/build.gradle" to """implementation("com.luciq.library:luciq:19.8.1")""",
            "Setup.kt" to "fun s() { Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA) }",
            "Pay.kt" to """
                @Composable fun Pay() {
                    TextField(value = cardNumber, label = { Text("Card Number") })
                }
            """.trimIndent(),
        )
        val f = runEngine(root)
        assertTrue("expected a card unmasked-field fail",
            f.any { it.check == "unmasked-field" && it.family == "card" && it.severity == LuciqMaskingEngine.Severity.FAIL })
    }

    @Test
    fun `inline luciqPrivate marker clears the field`() {
        val root = tempRoot(
            "app/build.gradle" to """implementation("com.luciq.library:luciq:19.8.1")""",
            "Setup.kt" to "fun s() { Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA) }",
            "Pay.kt" to """
                @Composable fun Pay() {
                    TextField(value = cardNumber, modifier = Modifier.luciqPrivate(), label = { Text("Card") })
                }
            """.trimIndent(),
        )
        val f = runEngine(root)
        assertTrue("masked card field must not be reported",
            f.none { it.check == "unmasked-field" && it.family == "card" })
    }

    @Test
    fun `email warns at none but fails at gdpr`() {
        val files = arrayOf(
            "app/build.gradle" to """implementation("com.luciq.library:luciq:19.8.1")""",
            "Setup.kt" to "fun s() { Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA); val consent = true }",
            "Profile.kt" to """
                @Composable fun P() { TextField(value = email, label = { Text("Email") }) }
            """.trimIndent(),
        )
        val none = runEngine(tempRoot(*files), "none")
        assertTrue("email is soft at none",
            none.any { it.family == "email" && it.severity == LuciqMaskingEngine.Severity.WARN })

        val gdpr = runEngine(tempRoot(*files), "gdpr")
        assertTrue("email is hard at gdpr",
            gdpr.any { it.family == "email" && it.severity == LuciqMaskingEngine.Severity.FAIL })
    }

    @Test
    fun `gdpr input floor flags an unnamed input`() {
        val root = tempRoot(
            "app/build.gradle" to """implementation("com.luciq.library:luciq:19.8.1")""",
            "Setup.kt" to "fun s() { Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA); val consent = true }",
            "Login.kt" to """@Composable fun L() { TextField(value = query, label = { Text("Search") }) }""",
        )
        assertTrue("unnamed input must be clean at none",
            runEngine(root, "none").none { it.family == "input" })
        assertTrue("unnamed input is a candidate at gdpr",
            runEngine(root, "gdpr").any { it.family == "input" && it.severity == LuciqMaskingEngine.Severity.FAIL })
    }

    @Test
    fun `custom keyword family from luciq_yml is recognized`() {
        val root = tempRoot(
            "luciq.yml" to """
                pii_masking:
                  compliance: none
                  keywords:
                    account: [loyaltyId, membershipNo]
            """.trimIndent(),
            "app/build.gradle" to """implementation("com.luciq.library:luciq:19.8.1")""",
            "Setup.kt" to "fun s() { Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA) }",
            "Profile.kt" to """
                @Composable fun P() {
                    TextField(value = loyaltyId, label = { Text("Loyalty") })
                    TextField(value = membership_no, label = { Text("Member") })
                }
            """.trimIndent(),
        )
        val f = runEngine(root)
        // One stem (membershipNo) must also match the snake_case membership_no.
        assertEquals("both account fields flagged", 2, f.count { it.family == "account" })
    }

    @Test
    fun `pci refuses a card waiver`() {
        val root = tempRoot(
            "app/build.gradle" to """implementation("com.luciq.library:luciq:19.8.1")""",
            "Setup.kt" to "fun s() { Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA) }",
            "Pay.kt" to """
                @Composable fun Pay() {
                    TextField(value = savedCard, label = { Text("Saved card") }) // luciq-mask-ignore
                }
            """.trimIndent(),
        )
        assertTrue("card waiver accepted at none",
            runEngine(root, "none").none { it.family == "card" })
        assertTrue("card waiver refused at pci",
            runEngine(root, "pci").any { it.family == "card" && it.severity == LuciqMaskingEngine.Severity.FAIL })
    }

    @Test
    fun `posture - no auto-mask configured is a hard fail`() {
        val root = tempRoot(
            "app/build.gradle" to """implementation("com.luciq.library:luciq:19.8.1")""",
            "Empty.kt" to "fun noop() {}",
        )
        assertTrue("missing auto-mask config must fail",
            runEngine(root).any { it.check == "auto-mask-config" && it.severity == LuciqMaskingEngine.Severity.FAIL })
    }

    @Test
    fun `posture - network disabled and flag-secure override are hard fails`() {
        val root = tempRoot(
            "app/build.gradle" to """implementation("com.luciq.library:luciq:19.8.1")""",
            "Setup.kt" to """
                fun s() {
                    Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA)
                    Luciq.setNetworkAutoMaskingState(Feature.State.DISABLED)
                    Luciq.ignoreFlagSecure(true)
                }
            """.trimIndent(),
        )
        val f = runEngine(root)
        assertTrue(f.any { it.check == "network-disabled" && it.severity == LuciqMaskingEngine.Severity.FAIL })
        assertTrue(f.any { it.check == "flag-secure" && it.severity == LuciqMaskingEngine.Severity.FAIL })
    }

    @Test
    fun `posture - old sdk version fails network check`() {
        val root = tempRoot(
            "app/build.gradle" to """implementation("com.luciq.library:luciq:13.0.0")""",
            "Setup.kt" to "fun s() { Luciq.setAutoMaskScreenshotsTypes(MaskingType.MEDIA) }",
        )
        assertTrue("sdk < 14.2.0 must fail",
            runEngine(root).any { it.check == "network-sdk-version" && it.severity == LuciqMaskingEngine.Severity.FAIL })
    }

    @Test
    fun `compliance presets match the Python tool`() {
        // Mirror of COMPLIANCE_PRESETS in luciq_masking_linter.py. If the Python tool's
        // presets change, this fails until LuciqMaskingEngine is updated in lockstep.
        data class Expected(
            val hard: Set<String>, val media: Boolean, val consent: Boolean,
            val forbidCard: Boolean, val maskAll: Boolean,
        )
        val base = setOf("card", "ssn", "credentials")
        val all = LuciqMaskingEngine.FAMILY_ORDER.toSet() + "input"
        val expected = mapOf(
            "none" to Expected(base, false, false, false, false),
            "soc2" to Expected(base, false, false, false, false),
            "pci" to Expected(base, false, false, true, false),
            "gdpr" to Expected(
                setOf("email", "phone", "name", "address", "dob", "ssn", "card", "credentials", "input"),
                false, true, false, true),
            "hipaa" to Expected(all, true, true, false, true),
        )
        for ((name, e) in expected) {
            val c = LuciqMaskingEngine.COMPLIANCE_PRESETS.getValue(name)
            assertEquals("$name hard families", e.hard, c.hardFamilies)
            assertEquals("$name requireMedia", e.media, c.requireMedia)
            assertEquals("$name consentRequired", e.consent, c.consentRequired)
            assertEquals("$name forbidCardWaiver", e.forbidCard, c.forbidCardWaiver)
            assertEquals("$name maskAllInputs", e.maskAll, c.maskAllInputs)
        }
    }

    @Test
    fun `parity with SampleAppAndroid under gdpr`() {
        val sample = File("../../sampleApp/SampleAppAndroid").absoluteFile
        assumeTrue("SampleAppAndroid not present; skipping parity check", sample.isDirectory)

        // Walk like the detector does: skip build dirs, keep sources + build scripts.
        val skip = setOf("build", ".git", ".gradle", ".idea", ".kotlin")
        val sources = sample.walkTopDown()
            .onEnter { it == sample || it.name !in skip }
            .filter { it.isFile && (it.name in setOf("build.gradle", "build.gradle.kts") ||
                it.name.endsWith(".kt") || it.name.endsWith(".java")) }
            .map { LuciqMaskingEngine.SourceFile(it.relativeTo(sample).path, it, it.readText()) }
            .toList()

        val findings = LuciqMaskingEngine.run(sources, sample) // luciq.yml → gdpr
        assertEquals("hard fails should match the Python gate (gdpr)", 15, fails(findings))
        assertEquals("warns should match the Python gate (gdpr)", 5, warns(findings))
    }
}
