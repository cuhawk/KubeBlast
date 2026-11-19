import json

from jinja2 import Environment

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>KubeBlast authorization graph</title>
<style>
body{margin:0;background:#101923;color:#eef5ff;font:16px system-ui}
header,main{padding:1rem 2rem} header{border-bottom:1px solid #405573}
h1{margin:0 0 .5rem} select{max-width:100%;padding:.4rem;margin-left:.5rem}
#graph{display:block;width:100%;min-height:360px;background:#162435;border-radius:.5rem}
.node{cursor:pointer} .node:focus circle,.node:hover circle{stroke:white;stroke-width:4}
#edges{overflow-wrap:anywhere} #edges li{margin:.5rem 0}
</style></head><body>
<header><h1>KubeBlast authorization graph</h1>
<label for="route">View</label><select id="route"><option value="">Full graph</option></select></header>
<main><svg id="graph" aria-label="Authorization graph"></svg>
<h2>Relationships</h2><p id="selection" aria-live="polite"></p><ul id="edges"></ul></main>
<script id="report" type="application/json">{{ data }}</script>
<script>
const report = JSON.parse(document.getElementById("report").textContent);
const svg = document.getElementById("graph");
const select = document.getElementById("route");
const edges = document.getElementById("edges");
const selection = document.getElementById("selection");
const labels = new Map(report.nodes.map(node => [node.id, node.label]));
for (const [index, path] of report.paths.entries()) {
  select.add(new Option(labels.get(path.nodes[0]) + " → " + labels.get(path.nodes.at(-1))
    + " [" + path.impact + (path.conditional ? ", conditional" : "") + "]", index));
}
function element(tag, attrs, parent = svg) {
  const item = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs)) item.setAttribute(key, value);
  parent.append(item);
  return item;
}
function relationships(links, id) {
  edges.replaceChildren();
  for (const edge of links.filter(e => !id || e.source === id || e.target === id)) {
    const item = document.createElement("li");
    item.textContent = labels.get(edge.source) + " → " + labels.get(edge.target)
      + " · " + edge.rule + (edge.conditional ? " (conditional)" : "") + " · " + edge.evidence;
    edges.append(item);
  }
}
function draw() {
  const path = select.value === "" ? null : report.paths[Number(select.value)];
  const nodes = path ? path.nodes.map(id => report.nodes.find(node => node.id === id)) : report.nodes;
  const links = path ? path.edges : report.edges;
  svg.replaceChildren();
  const width = 900, step = 110, height = Math.max(400, Math.ceil(nodes.length / 5) * step + 50);
  svg.setAttribute("viewBox", "0 0 " + width + " " + height);
  const marker = element("marker", {id:"arrow", markerWidth:8, markerHeight:8, refX:7, refY:4, orient:"auto"}, element("defs", {}));
  element("path", {d:"M0,0 L8,4 L0,8 Z", fill:"#a1afc2"}, marker);
  const positions = new Map(nodes.map((node, i) => [node.id, [90 + i % 5 * 180, 55 + Math.floor(i / 5) * step]]));
  for (const edge of links) {
    const [x,y] = positions.get(edge.source);
    const [tx,ty] = positions.get(edge.target);
    const distance = Math.hypot(tx-x,ty-y) || 1;
    const dx = (tx-x)/distance, dy = (ty-y)/distance;
    const d = edge.source === edge.target
      ? `M${x-12},${y-12} C${x-50},${y-63} ${x+50},${y-63} ${x+12},${y-12}`
      : `M${x+dx*15},${y+dy*15} L${tx-dx*17},${ty-dy*17}`;
    element("path", {d, fill:"none", stroke:"#a1afc2",
      "stroke-dasharray":edge.conditional ? "4 3" : "none", "marker-end":"url(#arrow)"});
  }
  for (const node of nodes) {
    const [x,y] = positions.get(node.id);
    const group = element("g", {class:"node", tabindex:0, role:"button", "aria-label":node.label});
    const show = () => { selection.textContent = node.label; relationships(links, node.id); };
    group.addEventListener("click", show);
    group.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); show(); }
    });
    element("circle", {cx:x, cy:y, r:15, fill:node.impact ? "#db755c" : "#45b4ae"}, group);
    element("title", {}, group).textContent = node.label;
    element("text", {x, y:y+34, fill:"#eef5ff", "font-size":13, "text-anchor":"middle"}, group)
      .textContent = node.label.length > 23 ? node.label.slice(0, 22) + "…" : node.label;
  }
  selection.textContent = nodes.length + " nodes · " + links.length + " relationships";
  relationships(links);
}
select.addEventListener("change", draw);
draw();
</script></body></html>
"""


def render_html(report: dict) -> str:
    data = json.dumps(report).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return Environment().from_string(TEMPLATE).render(data=data)


def render_markdown(report: dict) -> str:
    def safe(value):
        return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("|", "&#124;").replace("\r", " ").replace("\n", " "))

    lines = ["# KubeBlast audit", "",
             f"{len(report['nodes'])} nodes, {len(report['findings'])} findings, "
             f"{len(report['paths'])} paths within {report['max_hops']} hops.",
             "", "## Findings", "", "| Rule | Source | Target | Evidence |",
             "| --- | --- | --- | --- |"]
    for edge in report["findings"]:
        lines.append("| " + " | ".join(safe(edge[key]) for key in ("rule", "source", "target", "evidence")) + " |")
    lines.extend(["", "## Highest-impact paths", ""])
    for path in report["paths"]:
        qualifier = " (conditional)" if path["conditional"] else ""
        lines.append(f"- Impact {path['impact']}{qualifier} · " + " → ".join(map(safe, path["nodes"])))
    lines.extend(["", "## Blast radius", ""])
    for start, radius in report["blast_radius"].items():
        lines.append(f"- {safe(start)} · {radius['score']} across {len(radius['targets'])} targets")
    return "\n".join(lines) + "\n"
