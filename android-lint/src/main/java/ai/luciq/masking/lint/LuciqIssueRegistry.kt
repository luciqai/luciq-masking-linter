package ai.luciq.masking.lint

import com.android.tools.lint.client.api.IssueRegistry
import com.android.tools.lint.client.api.Vendor
import com.android.tools.lint.detector.api.CURRENT_API
import com.android.tools.lint.detector.api.Issue

/**
 * Entry point AGP / the IDE load (via the `Lint-Registry-v2` jar-manifest attribute)
 * to discover the checks this module provides.
 */
class LuciqIssueRegistry : IssueRegistry() {

    override val issues: List<Issue> = LuciqMaskingGateDetector.ALL_ISSUES

    // The Lint API level this registry was compiled against.
    override val api: Int = CURRENT_API

    override val vendor: Vendor = Vendor(
        vendorName = "Luciq",
        feedbackUrl = "https://docs.luciq.ai",
        identifier = "luciq-masking-linter",
    )
}
