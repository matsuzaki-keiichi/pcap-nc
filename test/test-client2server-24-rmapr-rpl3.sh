#!/usr/bin/env bash

# case 24.
#                      client         network         server
# xxx/PCAP =>     RMAPRD/PCAP =>     {RMAPRD/PCAP} => RMAPRD/PCAP
#                                                   + SPP/PCAP
# SPP/PCAP <= SPP/RMAPRR/PCAP <= {SPP/RMAPRR/PCAP} <= SPP/RMAPRR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Command 

PCAPNC=../bin/pcap-nc
OPTSEND='--original-time --interval=0.001'
OPTSERV='--no-stdin -l 14800'
OPTCLNT='127.0.0.1 14800 --sleep=1'

echo starting client
$PCAPNC $OPTCLNT $OPTSEND $CHAN < test-spp.pcap --after=1.0 --check-reply --store-data=outdir/test-spp-out.pcap &

echo starting server
FIFO=/tmp/pcap-fifo
mkfifo $FIFO
$PCAPNC $OPTSERV --link-type=spw <$FIFO | ../bin/pcap-rmap-target $CHAN --send-data=test-spp.pcap >$FIFO
rm $FIFO
