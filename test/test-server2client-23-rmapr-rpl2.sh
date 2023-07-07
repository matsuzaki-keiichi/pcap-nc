#!/usr/bin/env bash

# case 23.
#                      server         network         client
# xxx/PCAP =>     RMAPRD/PCAP =>     {RMAPRD/PCAP} => RMAPRD/PCAP
#                                                   + SPP/PCAP
#             SPP/RMAPRR/PCAP <= {SPP/RMAPRR/PCAP} <= SPP/RMAPRR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Command

PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 14800'
OPTCLNT='127.0.0.1 14800 --no-stdin'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN < test-spp.pcap --after=1.0 --link-type=spw >outdir/test-rmapr-rpl-out.pcap &

sleep 1
echo starting client
FIFO=/tmp/pcap-fifo
mkfifo $FIFO
$PCAPNC $OPTCLNT --link-type=spw <$FIFO | ../bin/pcap-rmap-target $CHAN --send-data=test-spp.pcap >$FIFO
rm $FIFO