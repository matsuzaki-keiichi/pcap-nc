#!/usr/bin/env bash

# case 21.
#                  server       network       client
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Channel

PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN < test-spp.pcap &

sleep 1
echo starting client
$PCAPNC --no-stdin $OPTCLNT --link-type=spw >outdir/test-rmapr-out.pcap
