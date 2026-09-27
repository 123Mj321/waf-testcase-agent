import json
from pathlib import Path

from .models import TestReport


DEFAULT_REPORT_PATH = Path("artifacts/report.json")


def render_json_report(report: TestReport, indent: int = 2) -> str:
    return json.dumps(
        report.to_dict(),
        ensure_ascii=False,
        indent=indent,
        sort_keys=True,
    )


def write_json_report(
    report: TestReport, path: Path = DEFAULT_REPORT_PATH
) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_json_report(report) + "\n",
        encoding="utf-8",
    )
    return output_path
