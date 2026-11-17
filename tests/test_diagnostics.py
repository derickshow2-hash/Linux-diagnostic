import json
import tempfile
import unittest
from pathlib import Path

from app.analyzers.rules import analyze
from app.collectors.commands import run
from app.models import DiagnosticReport, Finding
from app.reports.export import export_html, export_json


class CollectorTests(unittest.TestCase):
    def test_missing_command_is_reported_without_exception(self):
        result=run(["this-command-does-not-exist-fedora-doctor"])
        self.assertFalse(result.available)
        self.assertIn("не найдена",result.error)


class AnalyzerTests(unittest.TestCase):
    def test_cache_alone_does_not_trigger_low_memory_finding(self):
        data={"performance":{"memory":{"percent":99,"available":2*1024**3,"cached":10*1024**3}}}
        self.assertFalse(any("памяти мало" in x.title for x in analyze(data)))

    def test_oom_signature_is_confirmed_and_actionable(self):
        data={"performance":{"oom_recent":{"stdout":"kernel: Out of memory: Killed process 42 (browser)"}}}
        f=analyze(data)[0]
        self.assertEqual(f.status,"confirmed")
        self.assertTrue(f.evidence)
        self.assertTrue(f.commands)

    def test_io_errors_do_not_claim_drive_failure(self):
        data={"storage":{"io_journal":{"stdout":"blk_update_request: I/O error, dev sda"}}}
        f=analyze(data)[0]
        self.assertIn("не доказывает физическую неисправность",f.explanation)

    def test_nonzero_smart_pending_sector_is_reported(self):
        raw="197 Current_Pending_Sector 0x0012 100 100 000 Old_age Always - 2"
        finding=analyze({"storage":{"smart_devices":[{"device":"/dev/sda","stdout":raw}]}})[0]
        self.assertEqual(finding.severity,"critical")
        self.assertIn("pending sectors",finding.evidence[0])

    def test_full_filesystem_detection(self):
        data={"storage":{"partitions":[{"mountpoint":"/","percent":97,"free":100}]}}
        self.assertEqual(analyze(data)[0].status,"confirmed")

    def test_gpu_and_kwin_correlation_is_not_causal_claim(self):
        data={"gpu":{"gpu_journal":{"stdout":"NVRM: Xid 79 NVIDIA"},"kwin_journal":{"stdout":"kwin: error while rendering"}}}
        finding=next(x for x in analyze(data) if "совпадают" in x.title)
        self.assertEqual(finding.status,"probable")
        self.assertIn("не устанавливают",finding.explanation)


class ReportTests(unittest.TestCase):
    def test_json_and_html_export(self):
        report=DiagnosticReport.create({"hostname":"test"},{"x":1},[Finding("Проблема","warning","confirmed",["evidence"])],0.1)
        with tempfile.TemporaryDirectory() as d:
            jp=Path(d)/"report.json"; hp=Path(d)/"report.html"
            export_json(report,jp); export_html(report,hp)
            parsed=json.loads(jp.read_text())
            self.assertEqual(parsed["findings"][0]["title"],"Проблема")
            self.assertIn("Проблема",hp.read_text())


if __name__=="__main__": unittest.main()
