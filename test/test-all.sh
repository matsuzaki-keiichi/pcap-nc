#!/bin/bash

rm -fr outdir
mkdir -p outdir

# SPP / PCAP => { SPP / RMAP Write Command (with reply) / PCAP } => RMAP Write Reply / PCAP

echo ./test-client2server-rmapw-rpl.sh 
./test-client2server-rmapw-rpl.sh

diff expected/test-rpl-out.pcap outdir/test-rpl-out.pcap
if [ $? -ne 0 ]; then
    echo test failed
    exit
fi

echo ./test-server2client-rmapw-rpl.sh 
./test-server2client-rmapw-rpl.sh

diff expected/test-rpl-out.pcap outdir/test-rpl-out.pcap
if [ $? -ne 0 ]; then
    echo test failed
    exit
fi

# SPP / PCAP => { SPP / RMAP Write Command (without reply) / PCAP } => SPP / PCAP

echo ./test-client2server-rmapw-spp.sh 
./test-client2server-rmapw-spp.sh

diff expected/test-spp-out.pcap outdir/test-spp-out.pcap
if [ $? -ne 0 ]; then
    echo test failed
    exit
fi

echo ./test-server2client-rmapw-spp.sh 
./test-server2client-rmapw-spp.sh

diff expected/test-spp-out.pcap outdir/test-spp-out.pcap
if [ $? -ne 0 ]; then
    echo test failed
    exit
fi

# SPP / PCAP => {SPP / RMAP Write Command (without reply) / PCAP} 

echo ./test-client2server-rmapw.sh 
./test-client2server-rmapw.sh

diff expected/test-rmapw-spp-out.pcap outdir/test-rmapw-spp-out.pcap
if [ $? -ne 0 ]; then
    echo test failed
    exit
fi

echo ./test-server2client-rmapw.sh 
./test-server2client-rmapw.sh

diff expected/test-rmapw-spp-out.pcap outdir/test-rmapw-spp-out.pcap
if [ $? -ne 0 ]; then
    echo test failed
    exit
fi

# {SPP / PCAP}

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

