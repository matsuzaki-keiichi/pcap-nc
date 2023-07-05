#!/bin/bash

function do_test(){
  echo $1
  $1
  diff $2 $3
  if [ $? -ne 0 ]; then  
    echo test failed
    exit
  fi
  rm -f $3
}

rm -fr outdir
mkdir -p outdir

# case 5.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#                 RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

do_test ./test-client2server-rmapw-rpl2.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap
do_test ./test-server2client-rmapw-rpl2.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap

# case 4.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => RMAPWR/PCAP

do_test ./test-client2server-rmapw-rpl.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap
do_test ./test-server2client-rmapw-rpl.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap

# case 3.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => SPP/PCAP

do_test ./test-client2server-rmapw-spp.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap
do_test ./test-server2client-rmapw-spp.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap

# case 2.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP

do_test ./test-client2server-rmapw.sh expected/test-rmapw-spp-out.pcap outdir/test-rmapw-spp-out.pcap
do_test ./test-server2client-rmapw.sh expected/test-rmapw-spp-out.pcap outdir/test-rmapw-spp-out.pcap

# case 1.
#                   Initiator         network         Target
#                    SPP/PCAP =>     {SPP/PCAP}    => SPP/PCAP

do_test ./test-client2server.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap
do_test ./test-server2client.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap

echo all test succeeded
