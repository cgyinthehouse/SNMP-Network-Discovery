import cytoscape, { ElementDefinition } from "cytoscape";
import type { Topology, DiscoveredDevice, DiscoverPayload } from "./types";

const form = document.getElementById("discover-form") as HTMLFormElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const deviceList = document.getElementById("device-list") as HTMLDivElement;
const resetButton = document.getElementById("reset-btn") as HTMLButtonElement;

const cy = cytoscape({
  container: document.getElementById("cy"),
  elements: [],
  style: [
    {
      selector: "node",
      style: {
        "background-color": "#1976d2",
        label: "data(label)",
        color: "#ffffff",
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
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        label: "data(label)",
        "font-size": "8px",
        "text-rotation": "autorotate",
        "text-margin-y": -10,
      },
    },
    {
      selector: ".router",
      style: {
        "background-color": "#ff9800",
      },
    },
    {
      selector: ".switch",
      style: {
        "background-color": "#4caf50",
      },
    },
    {
      selector: ".firewall",
      style: {
        "background-color": "#f44336",
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

async function fetchTopology(): Promise<void> {
  try {
    const response = await fetch("/api/topology");

    if (!response.ok) {
      throw new Error("Failed to load topology");
    }

    const data = (await response.json()) as Topology;
    renderTopology(data);
    await fetchDevices();
  } catch (error) {
    showMessage((error as Error).message, true);
  }
}

async function fetchDevices(): Promise<void> {
  const response = await fetch("/api/devices");

  if (!response.ok) {
    showMessage("Unable to load discovered devices", true);
    return;
  }

  const devices = (await response.json()) as DiscoveredDevice[];
  renderDeviceList(devices);
}

function renderTopology(data: Topology): void {
  const elements: ElementDefinition[] = [];

  data.nodes.forEach((node) => {
    elements.push({
      data: {
        id: node.id,
        label: node.label,
        ip: node.ip,
        type: node.type,
        model: node.model,
      },
      classes: node.type ? node.type.toLowerCase() : "",
    });
  });

  data.edges.forEach((edge) => {
    elements.push({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.label,
        protocol: edge.protocol,
        platform: edge.platform,
      },
    });
  });

  cy.json({ elements });
  cy.layout({ name: "cose", animate: true, fit: true, padding: 40 }).run();

  cy.on("tap", "node", (event: any) => {
    const nodeData = event.target.data();
    showMessage(
      `Device: ${nodeData.label} (${nodeData.type || "Unknown"})\nIP: ${nodeData.ip || "N/A"}\nModel: ${nodeData.model || "N/A"}`,
      false,
    );
  });
}

function renderDeviceList(devices: DiscoveredDevice[]): void {
  if (!devices || devices.length === 0) {
    deviceList.innerHTML = "<p>No devices discovered yet.</p>";
    return;
  }

  const items = devices
    .map((device) => {
      const deviceName = (device["Device Name"] as string) || (device["IP Address"] as string) || "Unknown";
      const deviceType = (device["Device Type"] as string) || "Unknown";
      const deviceIp = (device["IP Address"] as string) || "N/A";
      const deviceModel = (device["Model Number"] as string) || "N/A";

      return `
        <div class="device-card">
          <strong>${deviceName}</strong>
          <div>Type: ${deviceType}</div>
          <div>IP: ${deviceIp}</div>
          <div>Model: ${deviceModel}</div>
        </div>
      `;
    })
    .join("");

  deviceList.innerHTML = items;
}

async function discoverDevice(event: Event): Promise<void> {
  event.preventDefault();

  const formData = new FormData(form);
  const payload: DiscoverPayload = {
    ip: formData.get("ip") as string | null,
    version: Number(formData.get("version")),
    community: (formData.get("community") as string) || "public",
    user: formData.get("user") as string | null,
    auth_key: formData.get("auth_key") as string | null,
    priv_key: formData.get("priv_key") as string | null,
    auth_proto: (formData.get("auth_proto") as string) || "SHA",
    priv_proto: (formData.get("priv_proto") as string) || "AES",
  };

  try {
    showMessage("Discovering device...", false);

    const response = await fetch("/api/discover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error((data as { detail?: string }).detail || "Discovery failed");
    }

    showMessage(`Discovered ${(data as any).device["Device Name"] || payload.ip} successfully.`, false);
    await fetchTopology();
  } catch (error) {
    showMessage((error as Error).message, true);
  }
}

async function resetTopology(): Promise<void> {
  const response = await fetch("/api/reset", { method: "POST" });

  if (!response.ok) {
    showMessage("Failed to reset topology", true);
    return;
  }

  showMessage("Topology reset.", false);
  cy.elements().remove();
  deviceList.innerHTML = "<p>No devices discovered yet.</p>";
}

function showMessage(text: string, isError: boolean): void {
  messageBox.textContent = text;
  messageBox.className = isError ? "message error" : "message success";
}

form.addEventListener("submit", discoverDevice);
resetButton.addEventListener("click", resetTopology);

fetchTopology();
