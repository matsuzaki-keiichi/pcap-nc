#!/usr/bin/env bash

echo starting server
../bin/pcap-nc -l 14800 --interval=0.5 --after=5 < test-spp.pcap >/dev/null &
sleep 1
echo starting client
../bin/pcap-nc 127.0.0.1 14800 --link-type=spp >test-spp-out.pcap &

tail -f test-spp-out.pcap
