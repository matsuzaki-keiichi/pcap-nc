#!/usr/bin/env bash

echo "starting client (1sec delay)"
../bin/pcap-nc 127.0.0.1 14800 --interval=0.5 --original-time --sleep=1 < test-spp.pcap >/dev/null &
echo starting server
../bin/pcap-nc -l 14800 --link-type=spp | tee test-spp-out.pcap
