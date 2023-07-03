#!/bin/bash

rm -fr outdir
mkdir -p outdir

echo ./test-client2server.sh 
./test-client2server.sh

diff expected/test-spp-out.pcap outdir/test-spp-out.pcap
if [ $? -ne 0 ]; then
    echo test failed
    exit
fi

echo ./test-server2client.sh
./test-server2client.sh

diff expected/test-spp-out.pcap outdir/test-spp-out.pcap
if [ $? -ne 0 ]; then
    echo test failed
    exit
fi

