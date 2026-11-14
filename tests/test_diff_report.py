import json

from seeded import ISSUES, allowlist, build

from nhi_evidence import cli, config, engine, report
from nhi_evidence.diff import diff


def test_diff_clean_to_seeded():
    cfg = config.load()
    changes = diff(build(set()).snapshot(), build(set(ISSUES)).snapshot(), cfg)
    kinds = {(c["kind"], c["display_name"]) for c in changes}
    assert ("new_privileged_permission", "doc-archiver") in kinds
    assert ("new_privileged_role", "identity-automation") in kinds
    assert ("new_tenant_wide_consent", "MailMerge Pro") in kinds
    assert ("owner_removed", "reporting-export") in kinds  # carol removed, only dave left
    assert ("new_credential_on_privileged", "sharepoint-migrator") in kinds  # became privileged with its cert
    assert diff(build(set()).snapshot(), build(set()).snapshot(), cfg) == []


def test_report_and_scrub(tmp_path):
    t = build(set(ISSUES))
    snap = t.snapshot()
    findings = engine.evaluate(snap, config.load(), allowlist(t))
    report.write(snap, findings, tmp_path, scrub_domains=["lab.example"])
    text = (tmp_path / "report.md").read_text() + (tmp_path / "findings.json").read_text()
    assert t.tenant_id not in text and "lab.example" not in text
    assert json.loads((tmp_path / "findings.json").read_text())["meta"]["findings"] == 15
    assert "NHI2 Secret Leakage" in (tmp_path / "owasp_mapping.md").read_text()


def test_cli_check_and_diff(tmp_path, capsys):
    build(set()).snapshot().save(tmp_path / "a")
    build({"S05"}).snapshot().save(tmp_path / "b")
    assert cli.main(["check", str(tmp_path / "b"), "--out", str(tmp_path / "r")]) == 0
    assert cli.main(["diff", str(tmp_path / "a"), str(tmp_path / "b")]) == 1
    assert "Files.ReadWrite.All" in capsys.readouterr().out
