#!/bin/bash
# Usage: extract_module.sh <module_name>
# Example: extract_module.sh LenovoWmaPolicyDxe
#
# Searches the extracted dump tree for a module by name and copies its PE32
# body to t430u/extracted/modules/<module_name>.efi

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <module_name>"
    echo "Example: $0 LenovoWmaPolicyDxe"
    exit 1
fi

MODULE="$1"
DUMP_DIR="$HOME/byte-evolution-tracker/t430u/extracted/t430u_4mb_spi_backup.rom.dump"
OUT_DIR="$HOME/byte-evolution-tracker/t430u/extracted/modules"
mkdir -p "$OUT_DIR"

# Find the module directory (UEFITool names it "<n> <ModuleName>.efi")
MODULE_DIR=$(find "$DUMP_DIR" -type d -name "*${MODULE}.efi" 2>/dev/null | head -1)

if [ -z "$MODULE_DIR" ]; then
    echo "ERROR: Could not find module directory matching '$MODULE'"
    exit 1
fi

echo "Found module directory: $MODULE_DIR"

# Look for the PE32 body.bin under that module's directory
PE32_BODY=$(find "$MODULE_DIR" -path "*PE32*body.bin" 2>/dev/null | head -1)

if [ -z "$PE32_BODY" ]; then
    echo "ERROR: No PE32 body.bin found under $MODULE_DIR"
    echo "Contents:"
    find "$MODULE_DIR" -type f | head
    exit 1
fi

OUT_FILE="$OUT_DIR/${MODULE}.efi"
cp "$PE32_BODY" "$OUT_FILE"
echo "Copied: $PE32_BODY"
echo "    -> $OUT_FILE"
echo
file "$OUT_FILE"
ls -la "$OUT_FILE"
