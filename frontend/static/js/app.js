"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
var _cytoscape = /*#__PURE__*/ _interop_require_default(require("cytoscape"));
function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) {
    try {
        var info = gen[key](arg);
        var value = info.value;
    } catch (error) {
        reject(error);
        return;
    }
    if (info.done) {
        resolve(value);
    } else {
        Promise.resolve(value).then(_next, _throw);
    }
}
function _async_to_generator(fn) {
    return function() {
        var self = this, args = arguments;
        return new Promise(function(resolve, reject) {
            var gen = fn.apply(self, args);
            function _next(value) {
                asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value);
            }
            function _throw(err) {
                asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err);
            }
            _next(undefined);
        });
    };
}
function _interop_require_default(obj) {
    return obj && obj.__esModule ? obj : {
        default: obj
    };
}
function _ts_generator(thisArg, body) {
    var f, y, t, _ = {
        label: 0,
        sent: function() {
            if (t[0] & 1) throw t[1];
            return t[1];
        },
        trys: [],
        ops: []
    }, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype), d = Object.defineProperty;
    return d(g, "next", {
        value: verb(0)
    }), d(g, "throw", {
        value: verb(1)
    }), d(g, "return", {
        value: verb(2)
    }), typeof Symbol === "function" && d(g, Symbol.iterator, {
        value: function() {
            return this;
        }
    }), g;
    function verb(n) {
        return function(v) {
            return step([
                n,
                v
            ]);
        };
    }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while(g && (g = 0, op[0] && (_ = 0)), _)try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [
                op[0] & 2,
                t.value
            ];
            switch(op[0]){
                case 0:
                case 1:
                    t = op;
                    break;
                case 4:
                    _.label++;
                    return {
                        value: op[1],
                        done: false
                    };
                case 5:
                    _.label++;
                    y = op[1];
                    op = [
                        0
                    ];
                    continue;
                case 7:
                    op = _.ops.pop();
                    _.trys.pop();
                    continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                        _ = 0;
                        continue;
                    }
                    if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                        _.label = op[1];
                        break;
                    }
                    if (op[0] === 6 && _.label < t[1]) {
                        _.label = t[1];
                        t = op;
                        break;
                    }
                    if (t && _.label < t[2]) {
                        _.label = t[2];
                        _.ops.push(op);
                        break;
                    }
                    if (t[2]) _.ops.pop();
                    _.trys.pop();
                    continue;
            }
            op = body.call(thisArg, _);
        } catch (e) {
            op = [
                6,
                e
            ];
            y = 0;
        } finally{
            f = t = 0;
        }
        if (op[0] & 5) throw op[1];
        return {
            value: op[0] ? op[1] : void 0,
            done: true
        };
    }
}
var form = document.getElementById("discover-form");
var messageBox = document.getElementById("message");
var deviceList = document.getElementById("device-list");
var resetButton = document.getElementById("reset-btn");
var cy = (0, _cytoscape.default)({
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
                "text-max-width": "80"
            }
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
                "text-margin-y": -10
            }
        },
        {
            selector: ".router",
            style: {
                "background-color": "#ff9800"
            }
        },
        {
            selector: ".switch",
            style: {
                "background-color": "#4caf50"
            }
        },
        {
            selector: ".firewall",
            style: {
                "background-color": "#f44336"
            }
        }
    ],
    layout: {
        name: "cose",
        animate: true,
        fit: true,
        padding: 30
    }
});
function fetchTopology() {
    return _async_to_generator(function() {
        var response, data, error;
        return _ts_generator(this, function(_state) {
            switch(_state.label){
                case 0:
                    _state.trys.push([
                        0,
                        4,
                        ,
                        5
                    ]);
                    return [
                        4,
                        fetch("/api/topology")
                    ];
                case 1:
                    response = _state.sent();
                    if (!response.ok) {
                        throw new Error("Failed to load topology");
                    }
                    return [
                        4,
                        response.json()
                    ];
                case 2:
                    data = _state.sent();
                    renderTopology(data);
                    return [
                        4,
                        fetchDevices()
                    ];
                case 3:
                    _state.sent();
                    return [
                        3,
                        5
                    ];
                case 4:
                    error = _state.sent();
                    showMessage(error.message, true);
                    return [
                        3,
                        5
                    ];
                case 5:
                    return [
                        2
                    ];
            }
        });
    })();
}
function fetchDevices() {
    return _async_to_generator(function() {
        var response, devices;
        return _ts_generator(this, function(_state) {
            switch(_state.label){
                case 0:
                    return [
                        4,
                        fetch("/api/devices")
                    ];
                case 1:
                    response = _state.sent();
                    if (!response.ok) {
                        showMessage("Unable to load discovered devices", true);
                        return [
                            2
                        ];
                    }
                    return [
                        4,
                        response.json()
                    ];
                case 2:
                    devices = _state.sent();
                    renderDeviceList(devices);
                    return [
                        2
                    ];
            }
        });
    })();
}
function renderTopology(data) {
    var elements = [];
    data.nodes.forEach(function(node) {
        elements.push({
            data: {
                id: node.id,
                label: node.label,
                ip: node.ip,
                type: node.type,
                model: node.model
            },
            classes: node.type ? node.type.toLowerCase() : ""
        });
    });
    data.edges.forEach(function(edge) {
        elements.push({
            data: {
                id: edge.id,
                source: edge.source,
                target: edge.target,
                label: edge.label,
                protocol: edge.protocol,
                platform: edge.platform
            }
        });
    });
    cy.json({
        elements: elements
    });
    cy.layout({
        name: "cose",
        animate: true,
        fit: true,
        padding: 40
    }).run();
    cy.on("tap", "node", function(event) {
        var nodeData = event.target.data();
        showMessage("Device: ".concat(nodeData.label, " (").concat(nodeData.type || "Unknown", ")\nIP: ").concat(nodeData.ip || "N/A", "\nModel: ").concat(nodeData.model || "N/A"), false);
    });
}
function renderDeviceList(devices) {
    if (!devices || devices.length === 0) {
        deviceList.innerHTML = "<p>No devices discovered yet.</p>";
        return;
    }
    var items = devices.map(function(device) {
        var deviceName = device["Device Name"] || device["IP Address"] || "Unknown";
        var deviceType = device["Device Type"] || "Unknown";
        var deviceIp = device["IP Address"] || "N/A";
        var deviceModel = device["Model Number"] || "N/A";
        return '\n        <div class="device-card">\n          <strong>'.concat(deviceName, "</strong>\n          <div>Type: ").concat(deviceType, "</div>\n          <div>IP: ").concat(deviceIp, "</div>\n          <div>Model: ").concat(deviceModel, "</div>\n        </div>\n      ");
    }).join("");
    deviceList.innerHTML = items;
}
function discoverDevice(event) {
    return _async_to_generator(function() {
        var formData, payload, response, data, error;
        return _ts_generator(this, function(_state) {
            switch(_state.label){
                case 0:
                    event.preventDefault();
                    formData = new FormData(form);
                    payload = {
                        ip: formData.get("ip"),
                        version: Number(formData.get("version")),
                        community: formData.get("community") || "public",
                        user: formData.get("user"),
                        auth_key: formData.get("auth_key"),
                        priv_key: formData.get("priv_key"),
                        auth_proto: formData.get("auth_proto") || "SHA",
                        priv_proto: formData.get("priv_proto") || "AES"
                    };
                    _state.label = 1;
                case 1:
                    _state.trys.push([
                        1,
                        5,
                        ,
                        6
                    ]);
                    showMessage("Discovering device...", false);
                    return [
                        4,
                        fetch("/api/discover", {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify(payload)
                        })
                    ];
                case 2:
                    response = _state.sent();
                    return [
                        4,
                        response.json()
                    ];
                case 3:
                    data = _state.sent();
                    if (!response.ok) {
                        throw new Error(data.detail || "Discovery failed");
                    }
                    showMessage("Discovered ".concat(data.device["Device Name"] || payload.ip, " successfully."), false);
                    return [
                        4,
                        fetchTopology()
                    ];
                case 4:
                    _state.sent();
                    return [
                        3,
                        6
                    ];
                case 5:
                    error = _state.sent();
                    showMessage(error.message, true);
                    return [
                        3,
                        6
                    ];
                case 6:
                    return [
                        2
                    ];
            }
        });
    })();
}
function resetTopology() {
    return _async_to_generator(function() {
        var response;
        return _ts_generator(this, function(_state) {
            switch(_state.label){
                case 0:
                    return [
                        4,
                        fetch("/api/reset", {
                            method: "POST"
                        })
                    ];
                case 1:
                    response = _state.sent();
                    if (!response.ok) {
                        showMessage("Failed to reset topology", true);
                        return [
                            2
                        ];
                    }
                    showMessage("Topology reset.", false);
                    cy.elements().remove();
                    deviceList.innerHTML = "<p>No devices discovered yet.</p>";
                    return [
                        2
                    ];
            }
        });
    })();
}
function showMessage(text, isError) {
    messageBox.textContent = text;
    messageBox.className = isError ? "message error" : "message success";
}
form.addEventListener("submit", discoverDevice);
resetButton.addEventListener("click", resetTopology);
fetchTopology();


//# sourceMappingURL=app.js.map