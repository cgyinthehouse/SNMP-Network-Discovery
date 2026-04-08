#!/bin/bash
set -e

# Clean previous builds
rm -rf build dist *.spec

# Build the binary
echo "Building binary..."
uv run pyinstaller --onefile --name snmp-discovery-linux main.py

echo "Build complete. Binary is in dist/snmp-discovery-linux"
chmod +x dist/snmp-discovery-linux
