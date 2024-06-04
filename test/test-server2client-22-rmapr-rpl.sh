#!/usr/bin/env bash

# case 22.
#                  server       network       client
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP =+> SPP/RMAPRR/PCAP
#                                                SPP/PCAP =+

mkdir -p outdir

CHAN='--config=sample.json --channel=channel3' # RMAP Read Channel

PCAPNC='../bin/pcap-nc'
NC='stdbuf -i 0 -o 0 nc -w 10'
OPTSEND='--original-time --interval=0.001 --before=2'
OPTSERV='-l 12345'
OPTCLNT='127.0.0.1 12345'

echo starting server
$PCAPNC $OPTSERV $OPTSEND $CHAN < test-spp.pcap &

sleep 1
echo starting client
$NC $OPTCLNT | ../bin/pcap-rmap-target $CHAN --send-data=test-spp.pcap | ../bin/pcap-store --link-type=spw >outdir/test-rmapr-rpl-out.pcap
