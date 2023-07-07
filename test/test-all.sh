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


# case 24.
#               Initiator       network       Target
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP
#                                              + SPP/PCAP
#             RMAPRR/PCAP <= {RMAPRR/PCAP} <= RMAPRR/PCAP

do_test ./test-client2server-24-rmapr-rpl3.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap
do_test ./test-server2client-24-rmapr-rpl3.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap

# case 23.
#               Initiator       network       Target
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP
#                                              + SPP/PCAP
#             RMAPRR/PCAP <= {RMAPRR/PCAP} <= RMAPRR/PCAP

do_test ./test-client2server-23-rmapr-rpl2.sh expected/test-rmapr-rpl-out.pcap outdir/test-rmapr-rpl-out.pcap
do_test ./test-server2client-23-rmapr-rpl2.sh expected/test-rmapr-rpl-out.pcap outdir/test-rmapr-rpl-out.pcap

# case 22.
#               Initiator       network       Target
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP =+> RMAPRR/PCAP
#                                                SPP/PCAP =+

do_test ./test-client2server-22-rmapr-rpl.sh expected/test-rmapr-rpl-out.pcap outdir/test-rmapr-rpl-out.pcap
do_test ./test-server2client-22-rmapr-rpl.sh expected/test-rmapr-rpl-out.pcap outdir/test-rmapr-rpl-out.pcap

# case 21.
#               Initiator       network       Target
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP

do_test ./test-client2server-21-rmapr.sh expected/test-rmapr-out.pcap outdir/test-rmapr-out.pcap
do_test ./test-server2client-21-rmapr.sh expected/test-rmapr-out.pcap outdir/test-rmapr-out.pcap

# case 15.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#  (check) <=     RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

echo ./test-client2server-15-rmapw-rpl3.sh 
./test-client2server-15-rmapw-rpl3.sh
echo ./test-server2client-15-rmapw-rpl3.sh 
./test-server2client-15-rmapw-rpl3.sh 

# case 14.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#                 RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

do_test ./test-client2server-14-rmapw-rpl2.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap
do_test ./test-server2client-14-rmapw-rpl2.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap

# case 13.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => RMAPWR/PCAP

do_test ./test-client2server-13-rmapw-rpl.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap
do_test ./test-server2client-13-rmapw-rpl.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap

# case 12.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => SPP/PCAP

do_test ./test-client2server-12-rmapw-spp.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap
do_test ./test-server2client-12-rmapw-spp.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap

# case 11.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP

do_test ./test-client2server-11-rmapw.sh expected/test-rmapw-spp-out.pcap outdir/test-rmapw-spp-out.pcap
do_test ./test-server2client-11-rmapw.sh expected/test-rmapw-spp-out.pcap outdir/test-rmapw-spp-out.pcap

# case 1.
#                   Initiator         network         Target
#                    SPP/PCAP =>     {SPP/PCAP}    => SPP/PCAP

do_test ./test-client2server.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap
do_test ./test-server2client.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap

echo all test succeeded
