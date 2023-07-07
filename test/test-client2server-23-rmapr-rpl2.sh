#!/usr/bin/env bash

# case 22.
#                  client       network       server
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP =+> RMAPRR/PCAP
#                                                SPP/PCAP =+

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Command 
FIFO=/tmp/pcap-fifo
mkfifo $FIFO

PCAPNC=../bin/pcap-nc
OPTSEND='--original-time --interval=0.001'
OPTSERV='--no-stdin -l 14800'
OPTCLNT='127.0.0.1 14800 --sleep=1'

echo "starting client (1sec delay)"
$PCAPNC $OPTCLNT $OPTSEND $CHAN --after=1.0 < test-spp.pcap >outdir/test-rmapr-rpl-out.pcap &
echo starting server
$PCAPNC $OPTSERV --link-type=spw <$FIFO | ../bin/pcap-rmap-target $CHAN --send-data=test-spp.pcap >$FIFO

rm $FIFO

