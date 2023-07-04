#!/usr/bin/env bash

mkdir -p outdir

CHAN='--config=sample.json --channel=channel2'
NOBUF='stdbuf -i 0 -o 0'
FIFO=/tmp/pcap-fifo
mkfifo $FIFO

echo starting server
$NOBUF ../bin/pcap-nc -l 14800 --interval=0.001 --after=5 --original-time $CHAN < test-spp.pcap >outdir/test-rpl-out.pcap &
sleep 1
echo starting client
$NOBUF ../bin/pcap-replay --interval=0.0 --original-time <$FIFO | $NOBUF ../bin/pcap-nc --no-stdin 127.0.0.1 14800 --link-type=spw | $NOBUF ../bin/pcap-rmap-target $CHAN >$FIFO

rm $FIFO
