#!/bin/bash
# Test script for cpuinfo_spoof
# Run with: sudo ./test_cpuinfo.sh

echo "Testing cpuinfo_spoof..."
echo "This will verify that the BPF program loads without verifier errors."
echo ""

# Try to run cpuinfo_spoof for 2 seconds
timeout 2 ./cpuinfo_spoof 2>&1 &
PID=$!

# Wait a bit for it to load
sleep 1

# Check if process is still running (successful load)
if kill -0 $PID 2>/dev/null; then
    echo "✓ SUCCESS: cpuinfo_spoof loaded successfully!"
    echo "  The BPF program passed the verifier and is running."
    kill $PID 2>/dev/null
    exit 0
else
    echo "✗ FAILED: cpuinfo_spoof failed to load"
    echo "  Check the error messages above for verifier errors."
    exit 1
fi
