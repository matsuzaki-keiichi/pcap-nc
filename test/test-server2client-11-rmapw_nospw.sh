#!/usr/bin/env bash

# case 11.
#                      server                         client
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1' # RMAP Write Channel without Acknowledge

PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345'
OPTNOSPW='--no-spw-on-eth'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN $OPTNOSPW< test-spp.pcap &

sleep 1
echo starting client
$PCAPNC --no-stdin $OPTCLNT $OPTNOSPW --link-type=spp >outdir/test-rmapw-spp-out-nospw.pcap
