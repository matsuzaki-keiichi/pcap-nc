#!/usr/bin/env bash

# case 2.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1' # RMAP Write Command without Acknowledge
PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001'
OPTSERV='--no-stdin -l 14800'
OPTCLNT='127.0.0.1 14800 --sleep=1'

echo "starting client (1sec delay)"
$PCAPNC $OPTCLNT $OPTSEND $CHAN < test-spp.pcap >/dev/null &
echo starting server
$PCAPNC $OPTSERV --link-type=spp >outdir/test-rmapw-spp-out.pcap
