#!/bin/bash
# Disk Model Anti-VM Spoofer
# Spoofs VBOX HARDDISK to look like Samsung SSD 970

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔════════════════════════════════════════╗"
echo "║   Disk Model Anti-VM Spoofer           ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: Must run as root (use sudo)"
    exit 1
fi

# Kill any existing textreplace instances
pkill -9 textreplace 2>/dev/null || true

echo "[*] Starting disk model spoofer..."
echo ""
echo "Target files:"
echo "  /sys/block/sda/device/model"
echo "  /sys/block/sdb/device/model (if exists)"
echo ""
echo "Spoofing:"
echo "  'VBOX HARDDISK' → 'Samsung SSD 970'"
echo ""

# Note: Both strings must be same length (13 chars + newline)
# "VBOX HARDDISK" = 13 chars
# "Samsung SSD 970" = 15 chars, need to pad or truncate

# Option 1: Pad VBOX to match Samsung length
# "VBOX HARDDISK  " (15 chars with padding)
# "Samsung SSD 970" (15 chars)

# Actually, let's check the actual file first
echo "[*] Checking current disk model..."
if [ -f /sys/block/sda/device/model ]; then
    CURRENT=$(cat /sys/block/sda/device/model)
    echo "Current model: '$CURRENT'"
    LENGTH=${#CURRENT}
    echo "Length: $LENGTH characters"
else
    echo "WARNING: /sys/block/sda/device/model not found"
    echo "This VM might not have SCSI/SATA disks"
    echo "Exiting..."
    exit 1
fi

# Start textreplace for /sys/block/sda/device/model
# VBOX HARDDISK = 13 chars (no newline in sysfs files usually)
# Samsung SSD 970 = 15 chars
# We need same length, so: "VBOX HARDDISK  " (padded to 15)

cd "$SCRIPT_DIR"

# Spoof sda
./textreplace -f /sys/block/sda/device/model -i "VBOX HARDDISK  " -r "Samsung SSD 970" &
DISK_PID=$!

sleep 0.5

echo ""
echo "✓ Disk spoofing active!"
echo ""
echo "Test command:"
echo "  cat /sys/block/sda/device/model"
echo ""
echo "Expected output:"
echo "  Samsung SSD 970"
echo ""
echo "Press Ctrl+C to stop..."
echo ""

# Wait for interrupt
trap "echo ''; echo 'Stopping...'; kill $DISK_PID 2>/dev/null; exit 0" INT TERM

# Keep running
wait
