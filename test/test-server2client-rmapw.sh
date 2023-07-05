#!/usr/bin/env bash

# case 2.
#                      server                         client
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1' # RMAP Write Command without Acknowledge
PCAPNC='../bin/pcap-nc'
CLOPT='--no-stdin 127.0.0.1 14800'
SVOPT='-l 14800 --interval=0.001 --after=5 --original-time'

echo starting server
$PCAPNC $SVOPT $CHAN < test-spp.pcap >/dev/null &
sleep 1
echo starting client
$PCAPNC $CLOPT --link-type=spp >outdir/test-rmapw-spp-out.pcap
