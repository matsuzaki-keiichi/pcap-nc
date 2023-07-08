#!/usr/bin/env bash

# case 12.
#                      server                         client
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => SPP/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1' # RMAP Write Channel without Acknowledge

PCAPNC='../bin/pcap-nc'
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 14800'
OPTCLNT='127.0.0.1 14800'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN < test-spp.pcap &

sleep 1
echo starting client
$NC $OPTCLNT | ../bin/pcap-rmap-target $CHAN | ../bin/pcap-store --link-type=spp >outdir/test-spp-out.pcap
