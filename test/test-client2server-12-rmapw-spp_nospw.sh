#!/usr/bin/env bash

# case 12.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => SPP/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1' # RMAP Write Channel without Acknowledge

PCAPNC='../bin/pcap-nc'
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345 --sleep=1'
OPTNOSPW='--no-spw-on-eth'

echo starting client
$PCAPNC $OPTCLNT $OPTSEND $CHAN $OPTNOSPW< test-spp.pcap &

echo starting server
$NC $OPTSERV | ../bin/pcap-rmap-target $OPTNOSPW $CHAN --store-data outdir/test-spp-out-nospw.pcap >/dev/null
