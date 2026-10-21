"""run_demo.py refuses to stay silent about a web build without plugin code.

Regression (2026-10-21): a local `flutter build web` reused a stale
.dart_tool/flutter_build/*/web_plugin_registrant.dart that registered only
secure storage. The file picker and recorder fell back to native method
channels that do not exist in a browser, so every photo, video, file and voice
message failed before anything was uploaded. The demo now detects that.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import run_demo


def _build(tmp_path: Path, js: str) -> Path:
    (tmp_path / "main.dart.js").write_text(js, encoding="utf-8")
    return tmp_path


def test_a_complete_build_passes(tmp_path):
    js = "...__file_picker_web-file-input...assets/packages/record_web/assets/js/record.worklet.js..."
    assert run_demo.missing_web_plugins(_build(tmp_path, js)) == []


def test_a_stale_build_is_reported(tmp_path):
    missing = run_demo.missing_web_plugins(_build(tmp_path, "flutter_secure_storage only"))
    assert any("file picker" in m for m in missing)
    assert any("recorder" in m for m in missing)


def test_no_bundle_is_not_misreported(tmp_path):
    assert run_demo.missing_web_plugins(tmp_path) == []
