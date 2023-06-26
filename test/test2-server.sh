#!/usr/bin/env bash

../bin/pcap-nc -l 14800 --interval=0.5 --after=5 --original-time < test-spp.pcap >/dev/null
