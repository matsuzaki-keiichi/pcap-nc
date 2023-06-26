#!/usr/bin/env bash

echo starting client
../bin/pcap-nc 127.0.0.1 14800 --interval=0.1 < test-spp.pcap >/dev/null
