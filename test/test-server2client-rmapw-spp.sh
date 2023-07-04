#!/usr/bin/env bash

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1'

echo starting server
../bin/pcap-nc -l 14800 --interval=0.001 --after=5 --original-time $CHAN < test-spp.pcap >/dev/null &
sleep 1
echo starting client
../bin/pcap-nc --no-stdin 127.0.0.1 14800 --link-type=spp | ../bin/pcap-rmap-target $CHAN >outdir/test-spp-out.pcap
