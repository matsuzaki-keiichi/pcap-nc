#!/usr/bin/env bash

# case 15.
#                      server                         client
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#  (check) <=     RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Channel with Acknowledge

PCAPNC='../bin/pcap-nc'
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345'
OPTNOSPW='--no-spw-on-eth'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN $OPTNOSPW< test-spp.pcap --after=1.0 --check-reply &

sleep 1
echo starting client
FIFO=/tmp/pcap-fifo
mkfifo $FIFO
$NC $OPTCLNT <$FIFO | ../bin/pcap-rmap-target $CHAN $OPTNOSPW >$FIFO
rm $FIFO
