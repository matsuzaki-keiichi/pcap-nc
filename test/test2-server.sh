#!/usr/bin/env bash

../bin/pcap-nc -l 14800 --interval=0.5 --before=2 --original-time < test-spp.pcap >/dev/null
