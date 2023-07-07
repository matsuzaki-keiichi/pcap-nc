#!/usr/bin/env bash

# case 13.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Command with Acknowledge
PCAPNC=../bin/pcap-nc
OPTSEND='--original-time --interval=0.001'
OPTSERV='--no-stdin -l 14800'
OPTCLNT='127.0.0.1 14800 --sleep=1'

echo "starting client (1sec delay)"
$PCAPNC $OPTCLNT $OPTSEND $CHAN < test-spp.pcap >/dev/null &
echo starting server
$PCAPNC $OPTSERV --link-type=spw | ../bin/pcap-rmap-target $CHAN | ../bin/pcap-store --link-type=spw >outdir/test-rpl-out.pcap
