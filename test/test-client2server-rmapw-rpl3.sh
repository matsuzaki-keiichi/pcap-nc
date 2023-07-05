#!/usr/bin/env bash

# case 6.
#                      client                         server
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#  (check) <=     RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Command with Acknowledge
FIFO1=/tmp/pcap-fifo1
FIFO2=/tmp/pcap-fifo2
mkfifo $FIFO1 $FIFO2

PCAPNC='stdbuf -i 0 -o 0 ../bin/pcap-nc'
CLOPT1='127.0.0.1 14800 --sleep=1'
CLOPT2='--interval=0.001 --original-time'
SVOPT='--no-stdin -l 14800'

echo "starting client (1sec delay)"
../bin/pcap-replay $CLOPT2 --receive-reply=$FIFO2 $CHAN < test-spp.pcap | $PCAPNC --no-stdin $CLOPT1 --link-type=spw >$FIFO2 &

echo starting server
$PCAPNC $SVOPT --link-type=spw <$FIFO1 | ../bin/pcap-rmap-target $CHAN | ../bin/pcap-replay --interval=0.0 --original-time >$FIFO1

rm $FIFO1 $FIFO2
