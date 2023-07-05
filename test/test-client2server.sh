#!/usr/bin/env bash

# case 1.
#   client                  server
# SPP/PCAP => {SPP/PCAP} => SPP/PCAP

mkdir -p outdir

PCAPNC='../bin/pcap-nc'
CLOPT='127.0.0.1 14800 --interval=0.001 --original-time --sleep=1'
SVOPT='--no-stdin -l 14800'

echo "starting client (1sec delay)"
$PCAPNC $CLOPT < test-spp.pcap >/dev/null &
echo starting server
$PCAPNC $SVOPT --link-type=spp >outdir/test-spp-out.pcap
