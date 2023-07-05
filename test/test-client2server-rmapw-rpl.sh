#!/usr/bin/env bash

# case 4.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Command with Acknowledge
PCAPNC=../bin/pcap-nc
CLOPT='127.0.0.1 14800 --interval=0.001 --original-time --sleep=1'
SVOPT='--no-stdin -l 14800'

echo "starting client (1sec delay)"
$PCAPNC $CLOPT $CHAN < test-spp.pcap >/dev/null &
echo starting server
$PCAPNC $SVOPT --link-type=spw | ../bin/pcap-rmap-target $CHAN >outdir/test-rpl-out.pcap
