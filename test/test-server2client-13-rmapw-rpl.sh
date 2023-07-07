#!/usr/bin/env bash

# case 13.
#                      server                         client
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Command with Acknowledge
PCAPNC='../bin/pcap-nc'

OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 14800'
OPTCLNT='127.0.0.1 14800 --no-stdin'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN < test-spp.pcap >/dev/null &
sleep 1
echo starting client
$PCAPNC $OPTCLNT --link-type=spw | ../bin/pcap-rmap-target $CHAN | ../bin/pcap-store --link-type=spw >outdir/test-rpl-out.pcap
