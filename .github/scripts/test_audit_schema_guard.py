import unittest

import audit_schema_guard


class AuditSchemaGuardTests(unittest.TestCase):
    def test_not_applicable_without_guarded_files_or_rls_diff(self):
        result = audit_schema_guard.evaluate_guard(
            changed_files=["sentinel-core/docs/detections.md"],
            diff_text="",
            pr_body="",
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("no audit-schema/RLS changes", "\n".join(result.messages))

    def test_passes_with_distinct_audit_trailers(self):
        result = audit_schema_guard.evaluate_guard(
            changed_files=["sentinel-core/backend/migrations/versions/001_test.py"],
            diff_text="",
            pr_body="Audit-Reviewed-by: Kai\nAudit-Approved-by: Mir\n",
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("audit-schema/RLS guard satisfied", "\n".join(result.messages))

    def test_fails_when_approved_by_trailer_missing(self):
        result = audit_schema_guard.evaluate_guard(
            changed_files=["sentinel-core/backend/migrations/versions/001_test.py"],
            diff_text="",
            pr_body="Audit-Reviewed-by: Kai\n",
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("missing trailer: Audit-Approved-by", "\n".join(result.messages))

    def test_fails_when_names_match_case_insensitively(self):
        result = audit_schema_guard.evaluate_guard(
            changed_files=["sentinel-core/backend/migrations/versions/001_test.py"],
            diff_text="",
            pr_body="Audit-Reviewed-by: Mir\nAudit-Approved-by:  mir  \n",
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("must be two different people", "\n".join(result.messages))

    def test_rls_diff_is_guarded_even_when_path_is_not(self):
        result = audit_schema_guard.evaluate_guard(
            changed_files=["sentinel-core/docs/example.md"],
            diff_text=(
                "diff --git a/sentinel-core/docs/example.md b/sentinel-core/docs/example.md\n"
                "+++ b/sentinel-core/docs/example.md\n"
                "+ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;\n"
            ),
            pr_body="",
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("sentinel-core/docs/example.md", "\n".join(result.messages))


if __name__ == "__main__":
    unittest.main()
