#!/usr/bin/env bash

# case 23.
#                      server         network         client
# xxx/PCAP =>     RMAPRD/PCAP =>     {RMAPRD/PCAP} => RMAPRD/PCAP
#                                                   + SPP/PCAP
#             SPP/RMAPRR/PCAP <= {SPP/RMAPRR/PCAP} <= SPP/RMAPRR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Channel

PCAPNC='../bin/pcap-nc'
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345'
OPTNOSPW='--no-spw-on-eth'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN $OPTNOSPW< test-spp.pcap --after=1.0 --link-type=spw >outdir/test-rmapr-rpl-out-nospw.pcap &

sleep 1
echo starting client
FIFO=/tmp/pcap-fifo
mkfifo $FIFO
$NC $OPTCLNT <$FIFO | ../bin/pcap-rmap-target $CHAN $OPTNOSPW --send-data=test-spp.pcap >$FIFO
rm $FIFO
