#!/usr/bin/env bash

# case 5.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#                 RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Command with Acknowledge
FIFO=/tmp/pcap-fifo
mkfifo $FIFO

PCAPNC='stdbuf -i 0 -o 0 ../bin/pcap-nc'
CLOPT='127.0.0.1 14800 --interval=0.001 --original-time --sleep=1'
SVOPT='--no-stdin -l 14800'

echo "starting client (1sec delay)"
$PCAPNC $CLOPT $CHAN --link-type=spw < test-spp.pcap >outdir/test-rpl-out.pcap &

echo starting server
$PCAPNC $SVOPT --link-type=spw <$FIFO | ../bin/pcap-rmap-target $CHAN | ../bin/pcap-replay --interval=0.0 --original-time >$FIFO

rm $FIFO
