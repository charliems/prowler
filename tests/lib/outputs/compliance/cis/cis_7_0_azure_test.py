import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute,
    CIS_Requirement_Attribute_AssessmentStatus,
    CIS_Requirement_Attribute_Profile,
    Compliance,
)
from prowler.lib.check.models import CheckMetadata
from prowler.lib.outputs.compliance.cis.cis import get_cis_table
from prowler.lib.outputs.compliance.cis.cis_azure import AzureCIS

PROWLER_ROOT = Path(__file__).parents[5] / "prowler"
FRAMEWORK_KEY = "cis_7.0_azure"
FRAMEWORK_PATH = PROWLER_ROOT / "compliance" / "azure" / f"{FRAMEWORK_KEY}.json"
AZURE_SERVICES_PATH = PROWLER_ROOT / "providers" / "azure" / "services"

VALID_PROFILES = {p.value for p in CIS_Requirement_Attribute_Profile}
VALID_STATUSES = {s.value for s in CIS_Requirement_Attribute_AssessmentStatus}

# Section headings of CIS Microsoft Azure Foundations Benchmark v7.0.0 that hold
# recommendations. Sections 1-4 and 5.2 are introduction/reference only.
EXPECTED_SECTIONS = [
    "5 Identity Services",
    "6 Management and Governance Services",
    "7 Networking Services",
    "8 Security Services",
    "9 Storage Services",
]


def _framework():
    return Compliance.get_bulk("azure")[FRAMEWORK_KEY]


def _existing_azure_checks() -> set:
    return {
        metadata.stem.replace(".metadata", "")
        for metadata in AZURE_SERVICES_PATH.rglob("*.metadata.json")
    }


def _finding(check_id, status):
    return SimpleNamespace(
        provider="azure",
        account_uid="00000000-0000-0000-0000-000000000000",
        region="global",
        check_id=check_id,
        status=status,
        status_extended=f"{check_id} {status}",
        resource_uid="/subscriptions/00000000-0000-0000-0000-000000000000",
        resource_name="Security Contact",
        muted=False,
    )


class TestCIS7_0_Azure:
    def test_framework_is_discoverable(self):
        assert FRAMEWORK_KEY in Compliance.get_bulk("azure")

    def test_framework_metadata(self):
        framework = _framework()
        assert framework.Framework == "CIS"
        assert framework.Provider == "Azure"
        assert framework.Version == "7.0"
        assert framework.Name == "CIS Microsoft Azure Foundations Benchmark v7.0.0"
        assert len(framework.Requirements) == 128

    def test_profile_and_assessment_totals_match_benchmark(self):
        # Totals from the benchmark's own recommendation list (v7.0.0, 10-30-2026).
        framework = _framework()
        profiles = [req.Attributes[0].Profile for req in framework.Requirements]
        statuses = [
            req.Attributes[0].AssessmentStatus for req in framework.Requirements
        ]
        assert profiles.count("Level 1") == 73
        assert profiles.count("Level 2") == 55
        assert statuses.count("Automated") == 100
        assert statuses.count("Manual") == 28

    def test_requirement_ids_are_unique(self):
        ids = [req.Id for req in _framework().Requirements]
        assert len(ids) == len(set(ids))

    def test_each_requirement_has_one_cis_attribute(self):
        for req in _framework().Requirements:
            assert len(req.Attributes) == 1, f"{req.Id} must have exactly one attribute"
            attribute = req.Attributes[0]
            # Must not fall back to the Generic attribute model.
            assert isinstance(attribute, CIS_Requirement_Attribute), req.Id
            assert attribute.Profile in VALID_PROFILES
            assert attribute.AssessmentStatus in VALID_STATUSES
            assert attribute.Description, f"{req.Id} has an empty Description"
            assert attribute.AuditProcedure, f"{req.Id} has an empty AuditProcedure"

    def test_sections_and_subsections_match_requirement_ids(self):
        framework = _framework()
        sections = []
        for req in framework.Requirements:
            attribute = req.Attributes[0]
            section_number = attribute.Section.split(" ")[0]
            assert req.Id.split(".")[0] == section_number, req.Id
            if attribute.Section not in sections:
                sections.append(attribute.Section)
            if attribute.SubSection:
                subsection_number = attribute.SubSection.split(" ")[0]
                assert req.Id.startswith(f"{subsection_number}."), req.Id
        assert sections == EXPECTED_SECTIONS

    def test_all_mapped_checks_exist(self):
        existing = _existing_azure_checks()
        framework = json.loads(FRAMEWORK_PATH.read_text())
        unknown = {
            check
            for req in framework["Requirements"]
            for check in req["Checks"]
            if check not in existing
        }
        assert (
            not unknown
        ), f"Framework references unknown Azure checks: {sorted(unknown)}"

    def test_cis_table_groups_findings_by_v7_section(self, capsys, tmp_path):
        bulk_metadata = update_checks_metadata_with_compliance(
            Compliance.get_bulk("azure"), CheckMetadata.get_bulk("azure")
        )
        # The table is only rendered for more than one finding.
        findings = [
            # 8.3.9 (Level 2)
            SimpleNamespace(
                check_metadata=SimpleNamespace(CheckID="keyvault_rbac_enabled"),
                status="FAIL",
                muted=False,
            ),
            # 9.2.3 (Level 1)
            SimpleNamespace(
                check_metadata=SimpleNamespace(
                    CheckID="storage_secure_transfer_required_is_enabled"
                ),
                status="PASS",
                muted=False,
            ),
        ]
        get_cis_table(
            findings, bulk_metadata, FRAMEWORK_KEY, "output", str(tmp_path), False
        )
        output = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
        assert "CIS_7.0_AZURE" in output
        rows = {
            line.split("│")[2].strip(): line
            for line in output.splitlines()
            if line.count("│") >= 6
        }
        assert "FAIL(1)" in rows["8 Security Services"]
        assert "PASS(1)" in rows["9 Storage Services"]


class TestCIS7_0_Azure_AttackPathRiskLevelGuardrail:
    """8.1.17 maps the attack path notification check with a guardrail on the
    configurable minimal risk level: raising it to Critical makes a PASS untrustworthy.
    """

    REQUIREMENT_ID = "8.1.17"
    CHECK = "defender_attack_path_notifications_properly_configured"

    def _rows_for(self, audit_config):
        compliance = Compliance(**json.loads(FRAMEWORK_PATH.read_text()))
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider"
        ) as mock_gp:
            mock_gp.return_value.audit_config = audit_config
            out = AzureCIS(
                findings=[_finding(self.CHECK, "PASS")],
                compliance=compliance,
                file_path=None,
            )
        return [r for r in out._data if r.Requirements_Id == self.REQUIREMENT_ID]

    def test_critical_minimal_risk_level_forces_fail(self):
        rows = self._rows_for({"defender_attack_path_minimal_risk_level": "Critical"})
        assert rows
        assert all(r.Status == "FAIL" for r in rows)
        assert all("Configuration not valid" in r.StatusExtended for r in rows)

    def test_high_minimal_risk_level_keeps_pass(self):
        rows = self._rows_for({"defender_attack_path_minimal_risk_level": "High"})
        assert rows
        assert all(r.Status == "PASS" for r in rows)
