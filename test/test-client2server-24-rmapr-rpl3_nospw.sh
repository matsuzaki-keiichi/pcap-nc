#!/usr/bin/env bash

# case 24.
#                      client         network         server
# xxx/PCAP =>     RMAPRD/PCAP =>     {RMAPRD/PCAP} => RMAPRD/PCAP
#                                                   + SPP/PCAP
# SPP/PCAP <= SPP/RMAPRR/PCAP <= {SPP/RMAPRR/PCAP} <= SPP/RMAPRR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Channel

PCAPNC=../bin/pcap-nc
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345 --sleep=1'
OPTNOSPW='--no-spw-on-eth'

echo starting client
$PCAPNC $OPTCLNT $OPTSEND $CHAN $OPTNOSPW < test-spp.pcap --after=1.0 --check-reply --store-data=outdir/test-spp-out-nospw.pcap &

echo starting server
FIFO=/tmp/pcap-fifo
mkfifo $FIFO
$NC $OPTSERV <$FIFO | ../bin/pcap-rmap-target $CHAN $OPTNOSPW --send-data=test-spp.pcap >$FIFO
rm $FIFO
