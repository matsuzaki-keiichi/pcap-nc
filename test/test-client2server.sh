#!/usr/bin/env bash

../bin/pcap-nc -l 1234 --after=5 > out.pcap &
../bin/pcap-nc 127.0.0.1 1234 < test.pcap >/dev/null &
tail -f out.pcap
