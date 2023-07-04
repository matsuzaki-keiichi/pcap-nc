#!/usr/bin/env bash

mkdir -p outdir

CHAN='--config=sample.json --channel=channel1'

echo "starting client (1sec delay)"
../bin/pcap-nc 127.0.0.1 14800 --interval=0.001 --original-time --sleep=1 $CHAN < test-spp.pcap >/dev/null &
echo starting server
../bin/pcap-nc --no-stdin -l 14800 --link-type=spp | ../bin/pcap-rmap-target $CHAN >outdir/test-spp-out.pcap
