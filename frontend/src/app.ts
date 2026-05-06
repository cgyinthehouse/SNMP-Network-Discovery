import "./styles.css";
import cytoscape, { ElementDefinition } from "cytoscape";
import type { Topology } from "./types";

const cy = cytoscape({
  container: document.getElementById("cy"),
  elements: [],
  style: [
    {
      selector: "node",
      style: {
        "background-color": "#1976d2",
        label: "data(label)",
        color: "#000000",
        "text-valign": "center",
        "text-halign": "center",
        width: "40",
        height: "40",
        "font-size": "10px",
        "text-wrap": "wrap",
        "text-max-width": "80",
      },
    },
    {
      selector: "edge",
      style: {
        width: 2,
        "line-color": "#999999",
        "target-arrow-color": "#999999",
        "target-arrow-shape": "none",
        "curve-style": "bezier",
        "font-size": "8px",
      },
    },
  ],
  layout: {
    name: "cose",
    animate: true,
    fit: true,
    padding: 30,
  },
});

function setOverlay(text: string) {
  let el = document.getElementById("frontend-overlay") as HTMLDivElement | null;
  if (!el) {
    el = document.createElement("div");
    el.id = "frontend-overlay";
    el.style.position = "fixed";
    el.style.left = "0";
    el.style.right = "0";
    el.style.top = "0";
    el.style.bottom = "0";
    el.style.display = "flex";
    el.style.alignItems = "center";
    el.style.justifyContent = "center";
    el.style.background = "rgba(255,255,255,0.85)";
    el.style.zIndex = "9999";
    document.body.appendChild(el);
  }
  el.textContent = text;
}

function clearOverlay() {
  const el = document.getElementById("frontend-overlay");
  if (el) el.remove();
}

function renderTopology(data: Topology): void {
  const elements: ElementDefinition[] = [];

  data.nodes.forEach((node) => {
    const displayLabel = node.label || String(node.id);
    const macLabel = node.mac ? `\n${node.mac}` : "";
    elements.push({
      data: {
        id: String(node.id),
        label: displayLabel + macLabel,
        ip: node.ip,
        mac: node.mac,
        type: node.type,
        model: node.model,
      },
    });
  });

  data.edges.forEach((edge) => {
    elements.push({ data: { id: String(edge.id), source: String(edge.source), target: String(edge.target) } });
  });

  cy.json({ elements });
  cy.layout({ name: "cose", animate: true, fit: true, padding: 40 }).run();

  cy.on("tap", "node", (event: any) => {
    const nodeData = event.target.data();
    const shortLabel = (nodeData.label || "").split("\n")[0];
    const info = `Device: ${shortLabel}\nIP: ${nodeData.ip || "N/A"}\nModel: ${nodeData.model || "N/A"}\nMAC: ${nodeData.mac || "N/A"}`;
    const infoEl = document.createElement("div");
    infoEl.textContent = info;
    infoEl.style.position = "fixed";
    infoEl.style.bottom = "20px";
    infoEl.style.left = "20px";
    infoEl.style.background = "rgb(77, 70, 70)";
    infoEl.style.color = "#fff";
    infoEl.style.padding = "8px 10px";
    infoEl.style.borderRadius = "8px";
    infoEl.style.zIndex = "10000";
    infoEl.style.whiteSpace = "pre-line";
    document.body.appendChild(infoEl);
    setTimeout(() => infoEl.remove(), 4000);
  });
}

async function initAutoDiscover() {
  try {
    setOverlay("Determining local network...");
    let subnet = "192.168.1.0/24";
    try {
      const r = await fetch("/api/local_network");
      if (r.ok) {
        const j = await r.json();
        if (j && j.default_subnet) subnet = j.default_subnet;
      }
    } catch (e) {
      console.warn("local_network lookup failed, falling back to", subnet, e);
    }

    setOverlay(`Scanning ${subnet} (this may take a few minutes)...`);
    const scanResp = await fetch("/api/discovery/integrated-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subnet: subnet, snmp_version: 2, snmp_community: "public" }),
    });

    if (!scanResp.ok) {
      const err = await scanResp.text();
      throw new Error("Discovery failed: " + err);
    }

    setOverlay("Fetching topology...");
    const topoResp = await fetch("/api/topology");
    if (!topoResp.ok) throw new Error("Failed to fetch topology");
    const topology = (await topoResp.json()) as Topology;
    renderTopology(topology);
    clearOverlay();
  } catch (err) {
    console.error(err);
    setOverlay("Error: " + (err instanceof Error ? err.message : String(err)) + " — see console for details.");
  }
}

initAutoDiscover();
