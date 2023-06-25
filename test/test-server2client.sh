#!/usr/bin/env bash

../bin/pcap-nc -l 1234 --after=5 < test.pcap >/dev/null &
../bin/pcap-nc 127.0.0.1 1234 > out.pcap &
tail -f out.pcap
