#!/bin/bash

# =====================================================
# F9: Network Traffic Evidence Capture using tcpdump
#
# Usage:
#   ./capture.sh <name> <seconds>
#
# Example:
#   ./capture.sh portscan 20
#
# Run this script BEFORE launching the test traffic.
# =====================================================

# Input arguments
NAME=${1:-capture}
SECS=${2:-20}

# Create capture directory
CAPTURE_DIR="$HOME/sdn_captures"
mkdir -p "$CAPTURE_DIR"

echo "Starting network traffic capture..."
echo "Capture Name: $NAME"
echo "Duration: $SECS seconds"

# Capture traffic on switch interface s1-eth2
sudo timeout "$SECS" tcpdump \
    -i s1-eth2 \
    -w "$CAPTURE_DIR/${NAME}_s1-eth2.pcap" \
    tcp &

# Capture traffic on switch interface s1-eth3
sudo timeout "$SECS" tcpdump \
    -i s1-eth3 \
    -w "$CAPTURE_DIR/${NAME}_s1-eth3.pcap" \
    tcp &

# Wait for both captures to finish
wait

# Display completion message
echo ""
echo "======================================"
echo "Network traffic capture completed!"
echo "======================================"

echo "Saved files:"
echo "$CAPTURE_DIR/${NAME}_s1-eth2.pcap"
echo "$CAPTURE_DIR/${NAME}_s1-eth3.pcap"

echo ""
echo "Open the PCAP files in Wireshark."

echo "Useful Wireshark display filter:"
echo "tcp.flags.syn==1 && tcp.flags.ack==0"
