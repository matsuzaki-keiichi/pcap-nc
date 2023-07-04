#!/usr/bin/env bash

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2'
NOBUF='stdbuf -i 0 -o 0'
FIFO=/tmp/pcap-fifo
mkfifo $FIFO

echo "starting client (1sec delay)"
$NOBUF ../bin/pcap-nc 127.0.0.1 14800 --interval=0.01 --original-time --sleep=1 $CHAN --link-type=spw < test-spp.pcap >outdir/test-rpl-out.pcap &

echo starting server
$NOBUF ../bin/pcap-replay --interval=0.0 --original-time <$FIFO | $NOBUF ../bin/pcap-nc --no-stdin -l 14800 --link-type=spw | $NOBUF ../bin/pcap-rmap-target $CHAN >$FIFO

rm $FIFO
