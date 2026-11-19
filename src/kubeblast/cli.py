import argparse
import json
from pathlib import Path

from .graph import analyze, read_inventory
from .remediate import write_remediation
from .visualizer import render_html, render_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze local IAM and Kubernetes authorization files.")
    parser.add_argument("inputs", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-hops", type=int, default=8)
    args = parser.parse_args(argv)
    try:
        report = analyze(read_inventory(args.inputs), args.max_hops)
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (args.output / "report.md").write_text(render_markdown(report), encoding="utf-8")
        (args.output / "report.html").write_text(render_html(report), encoding="utf-8")
        write_remediation(report, args.output / "remediation")
    except (OSError, ValueError) as exc:
        parser.exit(2, f"kubeblast: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
