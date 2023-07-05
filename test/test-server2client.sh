#!/usr/bin/env bash

# case 1.
#   server                  client
# SPP/PCAP => {SPP/PCAP} => SPP/PCAP

mkdir -p outdir

PCAPNC='../bin/pcap-nc'
CLOPT='--no-stdin 127.0.0.1 14800'
SVOPT='-l 14800 --interval=0.001 --after=5 --original-time'

echo starting server
$PCAPNC $SVOPT < test-spp.pcap >/dev/null &
sleep 1
echo starting client
$PCAPNC $CLOPT --link-type=spp >outdir/test-spp-out.pcap
