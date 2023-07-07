#!/usr/bin/env bash

# case 14.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#                 RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Command with Acknowledge

PCAPNC='stdbuf -i 0 -o 0 ../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001'
OPTSERV='--no-stdin -l 14800'
OPTCLNT='127.0.0.1 14800 --sleep=1'

echo starting client
$PCAPNC $OPTCLNT $OPTSEND $CHAN < test-spp.pcap --link-type=spw >outdir/test-rpl-out.pcap &

echo starting server
FIFO=/tmp/pcap-fifo
mkfifo $FIFO
$PCAPNC $OPTSERV --link-type=spw <$FIFO | ../bin/pcap-rmap-target $CHAN >$FIFO
rm $FIFO
