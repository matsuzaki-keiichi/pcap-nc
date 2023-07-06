#!/usr/bin/env bash

# case 23.
#                  server       network       client
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP
#                                              + SPP/PCAP
#             RMAPRR/PCAP <= {RMAPRR/PCAP} <= RMAPRR/PCAP

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Command
FIFO=/tmp/pcap-fifo
mkfifo $FIFO

PCAPNC='../bin/pcap-nc'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTRSPN='--original-time --interval=0.0'
OPTSERV='-l 14800'
OPTCLNT='127.0.0.1 14800 --no-stdin'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN --after=1.0 --link-type=spw < test-spp.pcap >outdir/test-rmapr-rpl-out.pcap &
sleep 1
echo starting client
$PCAPNC $OPTCLNT --link-type=spw <$FIFO | ../bin/pcap-rmap-target $CHAN --send-data=test-spp.pcap | ../bin/pcap-replay $OPTRSPN >$FIFO

rm $FIFO
