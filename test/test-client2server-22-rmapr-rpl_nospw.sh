#!/usr/bin/env bash

# case 22.
#                  client       network       server
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP =+> SPP/RMAPRR/PCAP
#                                                SPP/PCAP =+

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Channel

PCAPNC=../bin/pcap-nc
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345 --sleep=1'
OPTNOSPW='--no-spw-on-eth'

echo starting client
$PCAPNC $OPTCLNT $OPTSEND $CHAN $OPTNOSPW< test-spp.pcap &

echo starting server
$NC $OPTSERV | ../bin/pcap-rmap-target $CHAN $OPTNOSPW --send-data=test-spp.pcap | ../bin/pcap-store --link-type=spw >outdir/test-rmapr-rpl-out-nospw.pcap
