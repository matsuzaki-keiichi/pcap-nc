#!/usr/bin/env bash

# case 6.
#                      server                         client
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#  (check) <=     RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Command with Acknowledge
FIFO1=/tmp/pcap-fifo1
FIFO2=/tmp/pcap-fifo2
mkfifo $FIFO1 $FIFO2

PCAPNC='stdbuf -i 0 -o 0 ../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001 --after=5'
OPTRSPN='--original-time --interval=0.0'
OPTSERV='-l 14800'
OPTCLNT='127.0.0.1 14800 --no-stdin'

SVOPT1='-l 14800'
SVOPT2='--interval=0.001 --after=5 --original-time'

echo starting server
../bin/pcap-replay $OPTSEND $CHAN --receive-reply $FIFO2 < test-spp.pcap | $PCAPNC --no-stdin $OPTSERV >$FIFO2 &
sleep 1
echo starting client
$PCAPNC $OPTCLNT --link-type=spw <$FIFO1 | ../bin/pcap-rmap-target $CHAN | ../bin/pcap-replay $OPTRSPN >$FIFO1

rm $FIFO1 $FIFO2
