#!/usr/bin/env bash

# case 1.
#   client                  server
# SPP/PCAP => {SPP/PCAP} => SPP/PCAP

mkdir -p outdir

PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001'
OPTSERV='--no-stdin -l 14800'
OPTCLNT='127.0.0.1 14800 --sleep=1'

echo "starting client (1sec delay)"
$PCAPNC $OPTCLNT $OPTSEND < test-spp.pcap >/dev/null &
echo starting server
$PCAPNC $OPTSERV --link-type=spp >outdir/test-spp-out.pcap
