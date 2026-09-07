#!/usr/bin/env python3
"""Hosted regressions for the actual release jq predicate and failure evidence."""

import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from release_sbom_smoke import describe_spdx, production_contract, run_stage


WORKFLOW = Path(".github/workflows/release.yml").read_text()
VALID = {
    "spdxVersion": "SPDX-2.3",
    "documentNamespace": "https://example.invalid/sbom/test",
    "packages": [{"SPDXID": "SPDXRef-Package", "name": "fixture"}],
    "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                       "relationshipType": "DESCRIBES",
                       "relatedSpdxElement": "SPDXRef-Package"}],
}


class ProductionPredicateTests(unittest.TestCase):
    def validate(self, document):
        _, predicate, _ = production_contract(WORKFLOW)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "require_sbom.jq"
            path.write_text(predicate)
            return subprocess.run(
                ["jq", "-e", "-f", str(path)], input=json.dumps(document),
                text=True, capture_output=True, check=False, timeout=10,
            ).returncode

    def test_accepts_both_spdx_description_encodings(self):
        self.assertEqual(self.validate(VALID), 0)
        direct = copy.deepcopy(VALID)
        del direct["relationships"]
        direct["documentDescribes"] = ["SPDXRef-Package"]
        self.assertEqual(self.validate(direct), 0)

    def test_rejects_missing_empty_and_wrong_type_required_contents(self):
        for key in ("spdxVersion", "documentNamespace", "packages", "relationships"):
            for invalid in (None, "", [], {}):
                document = copy.deepcopy(VALID)
                document[key] = invalid
                with self.subTest(key=key, invalid=invalid):
                    self.assertNotEqual(self.validate(document), 0)
            document = copy.deepcopy(VALID)
            del document[key]
            with self.subTest(missing=key):
                self.assertNotEqual(self.validate(document), 0)

    def test_rejects_wrong_document_relationship(self):
        for key, value in (("spdxElementId", "SPDXRef-Package"),
                           ("relationshipType", "CONTAINS")):
            document = copy.deepcopy(VALID)
            document["relationships"][0][key] = value
            self.assertNotEqual(self.validate(document), 0)

    def test_contract_extraction_fails_closed_on_drift(self):
        for old, new in (
            ("require_sbom.jq", "different.jq"),
            ("anchore/syft@sha256:", "anchore/syft:latest#"),
            ('-o "spdx-json=/out/', '-o "syft-json=/out/'),
        ):
            with self.subTest(old=old), self.assertRaises(ValueError):
                production_contract(WORKFLOW.replace(old, new))

    def test_harness_uses_changed_production_predicate(self):
        # A weakened production gate must change the executed regression, not
        # leave a copied test predicate reporting an unrelated green result.
        _, predicate, _ = production_contract(WORKFLOW.replace(
            '.packages | type == "array" and length > 0',
            '.packages | type == "array" and length >= 0',
        ))
        self.assertIn('length >= 0', predicate)


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        # Expected failure diagnostics must not create CI error annotations.
        self.output = io.StringIO()
        self.redirect = redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def test_failed_scanner_retains_distinct_status_and_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            output = work / "partial.spdx.json"
            results = {}
            passed = run_stage("syft-scan", [sys.executable, "-c",
                "import sys; print('scanner failed', file=sys.stderr); sys.exit(17)"],
                work, {"PATH": os.environ["PATH"]}, results)
            self.assertFalse(passed)
            self.assertEqual(json.loads((work / "status.json").read_text())[
                "syft-scan"]["exit_code"], 17)
            self.assertIn("scanner failed", (work / "syft-scan.stderr.txt").read_text())
            self.assertEqual(describe_spdx(output), {"file_exists": False})
            output.write_text('{"packages":')
            self.assertFalse(describe_spdx(output)["json_valid"])
            output.write_text(json.dumps(VALID))
            self.assertEqual(describe_spdx(output)["document_describes_relationships"], 1)

    def test_launch_failure_and_timeout_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            results = {}
            env = {"PATH": os.environ["PATH"]}
            self.assertFalse(run_stage("missing", [str(work / "missing")], work, env, results))
            self.assertEqual(results["missing"]["status"], "launch_error")
            self.assertFalse(run_stage("slow", [sys.executable, "-c",
                "import time; time.sleep(30)"], work, env, results, timeout=0.05))
            saved = json.loads((work / "status.json").read_text())
            self.assertEqual(saved["slow"]["status"], "timeout")
            self.assertEqual(saved["missing"]["status"], "launch_error")


if __name__ == "__main__":
    unittest.main()
