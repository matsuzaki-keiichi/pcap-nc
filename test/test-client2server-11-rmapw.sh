#!/usr/bin/env bash

# case 11.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1' # RMAP Write Channel without Acknowledge

PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345 --sleep=1'

echo starting client
$PCAPNC $OPTCLNT $OPTSEND $CHAN < test-spp.pcap &

echo starting server
$PCAPNC --no-stdin $OPTSERV --link-type=spp >outdir/test-rmapw-spp-out.pcap
