#!/usr/bin/env bash

# case 14.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#                 RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Command with Acknowledge
FIFO=/tmp/pcap-fifo
mkfifo $FIFO

PCAPNC='stdbuf -i 0 -o 0 ../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001'
OPTRSPN='--original-time --interval=0.0'
OPTSERV='--no-stdin -l 14800'
OPTCLNT='127.0.0.1 14800 --sleep=1'

echo "starting client (1sec delay)"
$PCAPNC $OPTCLNT $OPTSEND $CHAN --link-type=spw < test-spp.pcap >outdir/test-rpl-out.pcap &

echo starting server
$PCAPNC $OPTSERV --link-type=spw <$FIFO | ../bin/pcap-rmap-target $CHAN | ../bin/pcap-replay $OPTRSPN >$FIFO

rm $FIFO
