"""Tests for the Luciq PII Masking Linter. Stdlib unittest, no third-party deps.

Run:  python3 -m unittest discover -s tests   (from the pii_masking_linter/ folder)
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import luciq_masking_linter as lint  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def checks(result):
    return sorted({f.check for f in result.findings})


def fails(result):
    return [f for f in result.findings if f.severity == "fail"]


def families(result, check=None):
    return sorted(f.family for f in result.findings if check is None or f.check == check)


class AndroidViolations(unittest.TestCase):
    def setUp(self):
        # compliance comes from the fixture's luciq.yml (hipaa)
        self.r = lint.run(os.path.join(FIX, "android_violations"), mode="enforce")

    def test_blocks_release(self):
        self.assertEqual(self.r.exit_code, 1)

    def test_reads_compliance_from_yaml(self):
        self.assertEqual(self.r.compliance, "hipaa")

    def test_detects_platform(self):
        self.assertIn("android", self.r.platforms)

    def test_all_layers_flagged(self):
        for c in ("auto-mask-config", "network-disabled", "network-sdk-version", "flag-secure", "unmasked-field"):
            self.assertIn(c, checks(self.r), f"missing {c}")

    def test_custom_keyword_ssn_caught(self):
        # fiscalCode comes from luciq.yml keywords -> family ssn
        self.assertIn("ssn", families(self.r, "unmasked-field"))

    def test_email_and_credentials_caught(self):
        fams = families(self.r, "unmasked-field")
        self.assertIn("email", fams)
        self.assertIn("credentials", fams)


class AndroidClean(unittest.TestCase):
    def test_no_findings(self):
        r = lint.run(os.path.join(FIX, "android_clean"), mode="enforce")
        self.assertEqual(r.findings, [], msg=lint.format_report(r, FIX))
        self.assertEqual(r.exit_code, 0)


class IosViolations(unittest.TestCase):
    def setUp(self):
        self.r = lint.run(os.path.join(FIX, "ios_violations"), mode="enforce")

    def test_blocks_release(self):
        self.assertEqual(self.r.exit_code, 1)

    def test_no_automask_flagged(self):
        self.assertIn("auto-mask-config", checks(self.r))

    def test_network_disabled_flagged(self):
        self.assertIn("network-disabled", checks(self.r))

    def test_old_sdk_flagged(self):
        self.assertIn("network-sdk-version", [f.check for f in fails(self.r)])

    def test_credentials_hard_fail_email_warn_under_none(self):
        v2 = {f.family: f.severity for f in self.r.findings if f.check == "unmasked-field"}
        self.assertEqual(v2.get("credentials"), "fail")
        self.assertEqual(v2.get("email"), "warn")  # email is soft under 'none'


class IosClean(unittest.TestCase):
    def test_no_findings(self):
        r = lint.run(os.path.join(FIX, "ios_clean"), mode="enforce")
        self.assertEqual(r.findings, [], msg=lint.format_report(r, FIX))


class WaiverBehavior(unittest.TestCase):
    def test_waiver_accepted_under_none(self):
        r = lint.run(os.path.join(FIX, "android_waiver"), cli_compliance="none", mode="enforce")
        self.assertEqual(r.findings, [], msg=lint.format_report(r, FIX))
        self.assertEqual(r.exit_code, 0)

    def test_card_waiver_refused_under_pci(self):
        r = lint.run(os.path.join(FIX, "android_waiver"), cli_compliance="pci", mode="enforce")
        card_fail = [f for f in r.findings if f.family == "card" and f.severity == "fail"]
        self.assertTrue(card_fail, msg=lint.format_report(r, FIX))
        self.assertEqual(r.exit_code, 1)


class CommentedMaskingNotCounted(unittest.TestCase):
    """A commented-out masking marker / config must not be treated as real masking."""

    def _run(self, swift, tmp_path):
        os.makedirs(tmp_path, exist_ok=True)
        # an old SDK lockfile would add unrelated N2 noise; ship a current one
        with open(os.path.join(tmp_path, "Podfile.lock"), "w") as fh:
            fh.write("  - Luciq (19.0.0)\n")
        with open(os.path.join(tmp_path, "ViewController.swift"), "w") as fh:
            fh.write(swift)
        return lint.run(tmp_path, cli_compliance="none", mode="enforce")

    def test_commented_inline_marker_is_not_coverage(self):
        import tempfile
        tmp = os.path.join(tempfile.mkdtemp(), "proj")
        swift = (
            "class VC {\n"
            "    func setup() {\n"
            "        SessionReplay.autoMaskScreenshotOptions = [.labels]\n"
            "    }\n"
            "    var body: some View {\n"
            "        // password.luciqPrivate()\n"
            "        SecureField(\"pwd\", text: $password)\n"
            "    }\n"
            "}\n"
        )
        r = self._run(swift, tmp)
        creds = [f for f in r.findings if f.check == "unmasked-field" and f.family == "credentials"]
        self.assertTrue(creds, msg=lint.format_report(r, tmp))
        self.assertEqual(creds[0].severity, "fail")

    def test_commented_automask_config_is_not_coverage(self):
        import tempfile
        tmp = os.path.join(tempfile.mkdtemp(), "proj")
        swift = (
            "class VC {\n"
            "    func setup() {\n"
            "        // SessionReplay.autoMaskScreenshotOptions = [.textInputs, .labels]\n"
            "    }\n"
            "}\n"
        )
        r = self._run(swift, tmp)
        self.assertIn("auto-mask-config", checks(r), msg=lint.format_report(r, tmp))


class NewFeatures(unittest.TestCase):
    """Bare-waiver rejection, trailing-comment FPs, excludes, SARIF, fix hints."""

    def _ios_proj(self, swift):
        import tempfile
        tmp = os.path.join(tempfile.mkdtemp(), "proj")
        os.makedirs(os.path.join(tmp, "app"), exist_ok=True)
        with open(os.path.join(tmp, "Podfile.lock"), "w") as fh:
            fh.write("  - Luciq (19.0.0)\n")
        with open(os.path.join(tmp, "app", "VC.swift"), "w") as fh:
            fh.write("class VC {\n    func setup() {\n"
                     "        Luciq.setAutoMaskScreenshots([.labels])\n    }\n"
                     "    var body: some View {\n" + swift + "\n    }\n}\n")
        return tmp

    def test_bare_waiver_is_accepted(self):
        # `// luciq-mask-ignore` with no reason waives the field.
        tmp = self._ios_proj('        SecureField("pwd", text: $pwd)  // luciq-mask-ignore')
        r = lint.run(tmp, cli_compliance="none", mode="enforce")
        self.assertEqual([f for f in r.findings if f.family == "credentials"], [],
                         msg=lint.format_report(r, tmp))

    def test_legacy_waiver_spelling_still_works(self):
        tmp = self._ios_proj('        SecureField("pwd", text: $pwd)  // luciq-ignore')
        r = lint.run(tmp, cli_compliance="none", mode="enforce")
        self.assertEqual([f for f in r.findings if f.family == "credentials"], [],
                         msg=lint.format_report(r, tmp))

    def test_optional_reason_is_surfaced(self):
        tmp = self._ios_proj('        SecureField("pwd", text: $pwd)  '
                             '// luciq-mask-ignore: masked upstream')
        r = lint.run(tmp, cli_compliance="none", mode="enforce")
        self.assertEqual([f for f in r.findings if f.family == "credentials"], [],
                         msg=lint.format_report(r, tmp))

    def test_file_level_waiver_waives_all_fields(self):
        tmp = self._ios_proj('        // luciq-mask-ignore-file\n'
                             '        SecureField("pwd", text: $pwd)\n'
                             '        TextField("email", text: $email)')
        r = lint.run(tmp, cli_compliance="none", mode="enforce")
        self.assertEqual([f for f in r.findings if f.check == "unmasked-field"], [],
                         msg=lint.format_report(r, tmp))

    def test_file_level_card_waiver_still_refused_under_pci(self):
        tmp = self._ios_proj('        // luciq-mask-ignore-file\n'
                             '        TextField("cardNumber", text: $card)')
        r = lint.run(tmp, cli_compliance="pci", mode="enforce")
        self.assertTrue(any(f.family == "card" and f.severity == "fail"
                            for f in r.findings), msg=lint.format_report(r, tmp))

    def test_widget_in_trailing_comment_is_not_a_candidate(self):
        # TextField only appears inside a comment -> must not be flagged
        tmp = self._ios_proj('        doThing()  // see TextField docs')
        r = lint.run(tmp, cli_compliance="none", mode="enforce")
        self.assertEqual(r.findings, [], msg=lint.format_report(r, tmp))

    def test_fix_hint_present_in_message(self):
        tmp = self._ios_proj('        SecureField("pwd", text: $pwd)')
        r = lint.run(tmp, cli_compliance="none", mode="enforce")
        self.assertTrue(any("To fix:" in f.message for f in r.findings),
                        msg=lint.format_report(r, tmp))

    def test_exclude_skips_directory(self):
        tmp = self._ios_proj('        Text("ok")')
        os.makedirs(os.path.join(tmp, "generated"), exist_ok=True)
        with open(os.path.join(tmp, "generated", "Gen.swift"), "w") as fh:
            fh.write('TextField("ssn", text: $ssn)\n')
        dirty = lint.run(tmp, cli_compliance="none", mode="enforce")
        clean = lint.run(tmp, cli_compliance="none", mode="enforce", excludes=["generated"])
        self.assertTrue(any(f.family == "ssn" for f in dirty.findings))
        self.assertFalse(any(f.family == "ssn" for f in clean.findings))

    def test_sarif_is_valid_json(self):
        import json
        r = lint.run(os.path.join(FIX, "ios_violations"), mode="enforce")
        doc = json.loads(lint.format_sarif(r, os.path.join(FIX, "ios_violations")))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), len(r.findings))


class CustomKeywordMatching(unittest.TestCase):
    """Custom keyword stems are case- and separator-insensitive."""

    def _fam_of(self, name, keywords):
        families = lint.compile_families(keywords)
        for fam, rx in families:
            if rx.search(name):
                return fam
        return None

    def test_stem_matches_separator_variants(self):
        kw = {"member": ["membershipNo"]}
        for name in ("membershipNo", "membership_no", "membership-no",
                     "MEMBERSHIPNO", "userMembershipNoField"):
            self.assertEqual(self._fam_of(name, kw), "member", msg=name)

    def test_stem_does_not_overmatch_different_word(self):
        # membershipNo must not match membershipNumber (different trailing word)
        self.assertIsNone(self._fam_of("membershipNumber", {"member": ["membershipNo"]}))

    def test_single_word_stem_unaffected(self):
        self.assertEqual(self._fam_of("userTaxId", {"ssn": ["taxId"]}), "ssn")


class InputFloorScoping(unittest.TestCase):
    """The 'every input is a candidate' floor is GDPR/HIPAA-only."""

    def _proj(self, swift):
        import tempfile
        tmp = os.path.join(tempfile.mkdtemp(), "proj")
        os.makedirs(tmp, exist_ok=True)
        with open(os.path.join(tmp, "Podfile.lock"), "w") as fh:
            fh.write("  - Luciq (19.0.0)\n")
        with open(os.path.join(tmp, "VC.swift"), "w") as fh:
            fh.write("class VC {\n    func setup() {\n"
                     "        Luciq.setAutoMaskScreenshots([.labels])\n    }\n"
                     "    var body: some View {\n" + swift + "\n    }\n}\n")
        return tmp

    def test_generic_input_not_flagged_under_none(self):
        tmp = self._proj('        TextField("Search", text: $query)')
        r = lint.run(tmp, cli_compliance="none", mode="enforce")
        self.assertEqual([f for f in r.findings if f.check == "unmasked-field"], [],
                         msg=lint.format_report(r, tmp))

    def test_generic_input_flagged_under_gdpr(self):
        tmp = self._proj('        TextField("Search", text: $query)')
        r = lint.run(tmp, cli_compliance="gdpr", mode="enforce")
        inputs = [f for f in r.findings if f.check == "unmasked-field" and f.family == "input"]
        self.assertTrue(inputs, msg=lint.format_report(r, tmp))
        self.assertEqual(inputs[0].severity, "fail")

    def test_named_input_flagged_on_every_level(self):
        tmp = self._proj('        TextField("email", text: $email)')
        for level in ("none", "soc2", "pci", "gdpr", "hipaa"):
            r = lint.run(tmp, cli_compliance=level, mode="enforce")
            self.assertTrue(any(f.family == "email" for f in r.findings),
                            msg=f"{level}: {lint.format_report(r, tmp)}")


class ModeAndOverrides(unittest.TestCase):
    def test_warn_mode_never_blocks(self):
        r = lint.run(os.path.join(FIX, "ios_violations"), mode="warn")
        self.assertTrue(any(f.severity == "fail" for f in r.findings))
        self.assertEqual(r.exit_code, 0)  # warn mode reports but doesn't block

    def test_env_var_sets_compliance(self):
        os.environ["LUCIQ_COMPLIANCE"] = "hipaa"
        try:
            r = lint.run(os.path.join(FIX, "ios_clean"), mode="enforce")
            self.assertEqual(r.compliance, "hipaa")
        finally:
            del os.environ["LUCIQ_COMPLIANCE"]

    def test_cli_defaults_to_warn(self):
        # no --mode given -> warn, so a violating app never blocks via the CLI default
        code = lint.main([os.path.join(FIX, "ios_violations")])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
