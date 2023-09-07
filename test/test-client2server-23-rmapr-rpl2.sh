#!/usr/bin/env bash

# case 23.
#                      client         network         server
# xxx/PCAP =>     RMAPRD/PCAP =>     {RMAPRD/PCAP} => RMAPRD/PCAP
#                                                   + SPP/PCAP
#             SPP/RMAPRR/PCAP <= {SPP/RMAPRR/PCAP} <= SPP/RMAPRR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Channel

PCAPNC=../bin/pcap-nc
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001'
OPTSERV='-l 14800'
OPTCLNT='127.0.0.1 14800 --sleep=1'

echo starting client
$PCAPNC $OPTCLNT $OPTSEND $CHAN < test-spp.pcap --after=1.0 --link-type=spw >outdir/test-rmapr-rpl-out.pcap &

echo starting server
FIFO=/tmp/pcap-fifo
mkfifo $FIFO
$NC $OPTSERV <$FIFO | ../bin/pcap-rmap-target $CHAN --send-data=test-spp.pcap >$FIFO
rm $FIFO
