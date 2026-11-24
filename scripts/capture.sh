#!/bin/bash


NAME=${1:-capture}
SECS=${2:-20}


CAPTURE_DIR="$HOME/sdn_captures"
mkdir -p "$CAPTURE_DIR"

echo "Starting network traffic capture..."
echo "Capture Name: $NAME"
echo "Duration: $SECS seconds"

sudo timeout "$SECS" tcpdump \
    -i s1-eth2 \
    -w "$CAPTURE_DIR/${NAME}_s1-eth2.pcap" \
    tcp &


sudo timeout "$SECS" tcpdump \
    -i s1-eth3 \
    -w "$CAPTURE_DIR/${NAME}_s1-eth3.pcap" \
    tcp &


wait


echo ""
echo "-----------------------------------"
echo "Network traffic capture completed!"
echo "-----------------------------------"

echo "Saved files:"
echo "$CAPTURE_DIR/${NAME}_s1-eth2.pcap"
echo "$CAPTURE_DIR/${NAME}_s1-eth3.pcap"

echo ""
echo "Open the PCAP files in Wireshark."

echo "Useful Wireshark display filter:"
echo "tcp.flags.syn==1 && tcp.flags.ack==0"
