from pathlib import Path
from urllib.parse import quote


def render_sarif(report: dict) -> dict:
    def location(edge):
        path = Path(edge["evidence"])
        uri = path.as_uri() if path.is_absolute() else quote(path.as_posix(), safe="/")
        return {"physicalLocation": {"artifactLocation": {"uri": uri}}}

    results = []
    for edge in report["findings"]:
        results.append({
            "ruleId": edge["rule"],
            "level": "warning",
            "message": {"text": f"{edge['source']} can reach {edge['target']} via {edge['rule']}."},
            "locations": [location(edge)],
        })
    for path in report["paths"]:
        results.append({
            "ruleId": "authorization_path",
            "level": "error" if path["impact"] >= 7 else "note",
            "message": {"text": " → ".join(path["nodes"])},
            "locations": [location(path["edges"][0])],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {**location(edge), "message": {"text": edge["rule"]}}}
                for edge in path["edges"]
            ]}]}],
            "properties": {"impact": path["impact"], "conditional": path["conditional"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "KubeBlast", "rules": [
                {"id": name, "name": name} for name in sorted({result["ruleId"] for result in results})
            ]}},
            "results": results,
        }],
    }
