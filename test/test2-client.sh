#!/usr/bin/env bash

../bin/pcap-nc 127.0.0.1 14800 --link-type=spp | tee test-spp-out.pcap
