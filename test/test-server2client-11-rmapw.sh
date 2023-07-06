#!/usr/bin/env bash

# case 11.
#                      server                         client
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1' # RMAP Write Command without Acknowledge
PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 14800'
OPTCLNT='127.0.0.1 14800 --no-stdin'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN < test-spp.pcap >/dev/null &
sleep 1
echo starting client
$PCAPNC $OPTCLNT --link-type=spp >outdir/test-rmapw-spp-out.pcap
