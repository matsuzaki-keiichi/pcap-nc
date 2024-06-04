#!/usr/bin/env bash

#
# Delay test 6.
#
# server to client RMAP Write with reply with delay
#

#                      server                         client
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#                 RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2' # RMAP Write Channel with Acknowledge

PCAPNC='../bin/pcap-nc'
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN < test-spp.pcap --after=1.0 --link-type=spw >outdir/test-rpl-out-delay.pcap &

sleep 1
echo starting client
FIFO=/tmp/pcap-fifo
mkfifo $FIFO
$NC $OPTCLNT <$FIFO | ../bin/pcap-rmap-target $CHAN --delay=0.3 >$FIFO
rm $FIFO
