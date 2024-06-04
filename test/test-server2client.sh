#!/usr/bin/env bash

# case 1.
#   server                  client
# SPP/PCAP => {SPP/PCAP} => SPP/PCAP

mkdir -p outdir

PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345 --no-stdin'

echo starting server
$PCAPNC $OPTSERV $OPTSEND < test-spp.pcap &
sleep 1
echo starting client
$PCAPNC $OPTCLNT --link-type=spp >outdir/test-spp-out.pcap
