import cytoscape from "cytoscape";
const form = document.getElementById("discover-form");
const messageBox = document.getElementById("message");
const deviceList = document.getElementById("device-list");
const resetButton = document.getElementById("reset-btn");
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
async function fetchTopology() {
    try {
        const response = await fetch("/api/topology");
        if (!response.ok) {
            throw new Error("Failed to load topology");
        }
        const data = (await response.json());
        renderTopology(data);
        await fetchDevices();
    }
    catch (error) {
        showMessage(error.message, true);
    }
}
async function fetchDevices() {
    const response = await fetch("/api/devices");
    if (!response.ok) {
        showMessage("Unable to load discovered devices", true);
        return;
    }
    const devices = (await response.json());
    renderDeviceList(devices);
}
function renderTopology(data) {
    const elements = [];
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
    cy.on("tap", "node", (event) => {
        const nodeData = event.target.data();
        showMessage(`Device: ${nodeData.label} (${nodeData.type || "Unknown"})\nIP: ${nodeData.ip || "N/A"}\nModel: ${nodeData.model || "N/A"}`, false);
    });
}
function renderDeviceList(devices) {
    if (!devices || devices.length === 0) {
        deviceList.innerHTML = "<p>No devices discovered yet.</p>";
        return;
    }
    const items = devices
        .map((device) => {
        const deviceName = device["Device Name"] || device["IP Address"] || "Unknown";
        const deviceType = device["Device Type"] || "Unknown";
        const deviceIp = device["IP Address"] || "N/A";
        const deviceModel = device["Model Number"] || "N/A";
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
async function discoverDevice(event) {
    event.preventDefault();
    const formData = new FormData(form);
    const payload = {
        ip: formData.get("ip"),
        version: Number(formData.get("version")),
        community: formData.get("community") || "public",
        user: formData.get("user"),
        auth_key: formData.get("auth_key"),
        priv_key: formData.get("priv_key"),
        auth_proto: formData.get("auth_proto") || "SHA",
        priv_proto: formData.get("priv_proto") || "AES",
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
            throw new Error(data.detail || "Discovery failed");
        }
        showMessage(`Discovered ${data.device["Device Name"] || payload.ip} successfully.`, false);
        await fetchTopology();
    }
    catch (error) {
        showMessage(error.message, true);
    }
}
async function resetTopology() {
    const response = await fetch("/api/reset", { method: "POST" });
    if (!response.ok) {
        showMessage("Failed to reset topology", true);
        return;
    }
    showMessage("Topology reset.", false);
    cy.elements().remove();
    deviceList.innerHTML = "<p>No devices discovered yet.</p>";
}
function showMessage(text, isError) {
    messageBox.textContent = text;
    messageBox.className = isError ? "message error" : "message success";
}
form.addEventListener("submit", discoverDevice);
resetButton.addEventListener("click", resetTopology);
fetchTopology();
