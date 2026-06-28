import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Luciq PII Masking — Android Lint detector.
//
// A self-contained Android port of the Luciq PII-masking gate. Produces a lint.jar that
// an Android app consumes via `lintChecks("ai.luciq:luciq-masking-lint:<version>")`,
// giving findings in Android Studio and `./gradlew lint` (HTML/XML/SARIF) — and, because
// the hard-fail issues default to ERROR, a CI gate (`./gradlew lint`/`check` fails) with
// no Python required on Android.
//
// LuciqMaskingEngine.kt is a faithful Kotlin port of the Python `luciq_masking_linter.py`
// (Android adapter): same families, compliance dialing, custom luciq.yml keywords, and
// project posture. The Python CLI stays the cross-platform source of truth (it also does
// iOS); keep the regexes/markers/presets in LuciqMaskingEngine.kt in sync with
// BUILTIN_FAMILIES + COMPLIANCE_PRESETS + ADAPTERS["android"].
plugins {
    kotlin("jvm") version "2.0.21"
    `java-library`
    `maven-publish`
    signing
}

group = "ai.luciq"
// JitPack builds a requested tag and expects the published version to match it. It sets
// the VERSION env var to the requested coordinate; fall back to the release version for
// local builds / publishToMavenLocal (where VERSION is unset).
version = System.getenv("VERSION") ?: "0.1.0"

// Android Lint API. Convention: lint version = AGP version + 23.0.0 (AGP 9.0.1 → 32.0.1).
val lintVersion = "32.0.1"

repositories {
    google()
    mavenCentral()
}

java {
    // Lint 32.x (AGP 9.x) targets JDK 17. Bytecode 17 so it loads in the IDE + Gradle.
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    // Maven Central requires a sources jar and a javadoc jar. For this Kotlin-only lint
    // module the javadoc jar is effectively empty, which still satisfies Central's gate.
    withSourcesJar()
    withJavadocJar()
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
        // Lint 32.x (AGP 9) ships IntelliJ/lint artifacts compiled with a newer Kotlin
        // (2.2.x metadata). Their public API is compatible with the 2.0.x compiler we use;
        // skip the metadata version gate so it doesn't abort with an "incompatible version
        // of Kotlin" error. (AGP injects this automatically; a standalone build must opt in.)
        freeCompilerArgs.add("-Xskip-metadata-version-check")
    }
}

dependencies {
    compileOnly("com.android.tools.lint:lint-api:$lintVersion")
    compileOnly("com.android.tools.lint:lint-checks:$lintVersion")

    testImplementation("com.android.tools.lint:lint-api:$lintVersion")
    testImplementation("com.android.tools.lint:lint-tests:$lintVersion")
    testImplementation("junit:junit:4.13.2")
}

tasks.jar {
    manifest {
        // How AGP / the IDE discover the registry inside this jar.
        attributes("Lint-Registry-v2" to "ai.luciq.masking.lint.LuciqIssueRegistry")
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            artifactId = "luciq-masking-lint"
            pom {
                name.set("Luciq PII Masking — Android Lint")
                description.set(
                    "Standalone Android Lint gate for Luciq PII-masking gaps: a Kotlin port " +
                        "of the luciq-masking-linter engine that blocks ./gradlew lint/CI on " +
                        "unmasked PII — no Python required.",
                )
                url.set("https://github.com/luciqai/luciq-masking-linter")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("luciq")
                        name.set("Luciq")
                        organization.set("Luciq")
                        organizationUrl.set("https://luciq.ai")
                    }
                }
                scm {
                    url.set("https://github.com/luciqai/luciq-masking-linter")
                    connection.set("scm:git:https://github.com/luciqai/luciq-masking-linter.git")
                    developerConnection.set("scm:git:ssh://git@github.com/luciqai/luciq-masking-linter.git")
                }
            }
        }
    }
    // Local target works today: `./gradlew publishToMavenLocal`.
    //
    // For Maven Central, publish through the SAME pipeline the Luciq Android SDK
    // (ai.luciq.library:luciq) already uses — the `ai.luciq` namespace is already verified
    // there, so this only needs a publishing token + signing key from that pipeline. Add the
    // Central Portal repository (or the team's publish plugin) to match their setup.
}

// GPG signing — required by Maven Central. Active only when a key is supplied (CI secrets
// SIGNING_KEY + SIGNING_PASSWORD, or -PsigningKey/-PsigningPassword), so local builds and
// `publishToMavenLocal` keep working unsigned.
signing {
    val signingKey = System.getenv("SIGNING_KEY") ?: findProperty("signingKey") as String?
    val signingPassword = System.getenv("SIGNING_PASSWORD") ?: findProperty("signingPassword") as String?
    if (!signingKey.isNullOrBlank() && signingPassword != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications["maven"])
    }
}
