#!/usr/bin/env bash

echo starting server
../bin/pcap-nc -l 14800 --link-type=spp | tee test-spp-out.pcap

