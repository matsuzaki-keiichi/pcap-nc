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

echo ./test-pcap-replay-options.sh
./test-pcap-replay-options.sh
if [ $? -ne 0 ]; then  
  echo test failed
  exit
fi

echo ./test-pcap-rmap-target-options.sh
./test-pcap-rmap-target-options.sh
if [ $? -ne 0 ]; then  
  echo test failed
  exit
fi


# case 24.
#               Initiator       network       Target
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP
#                                              + SPP/PCAP
#             RMAPRR/PCAP <= {RMAPRR/PCAP} <= RMAPRR/PCAP

do_test ./test-client2server-24-rmapr-rpl3.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap
do_test ./test-server2client-24-rmapr-rpl3.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap

do_test ./test-client2server-24-rmapr-rpl3_nospw.sh expected/test-spp-out.pcap outdir/test-spp-out-nospw.pcap
do_test ./test-server2client-24-rmapr-rpl3_nospw.sh expected/test-spp-out.pcap outdir/test-spp-out-nospw.pcap

# case 23.
#               Initiator       network       Target
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP
#                                              + SPP/PCAP
#             RMAPRR/PCAP <= {RMAPRR/PCAP} <= RMAPRR/PCAP

do_test ./test-client2server-23-rmapr-rpl2.sh expected/test-rmapr-rpl-out.pcap outdir/test-rmapr-rpl-out.pcap
do_test ./test-server2client-23-rmapr-rpl2.sh expected/test-rmapr-rpl-out.pcap outdir/test-rmapr-rpl-out.pcap

do_test ./test-client2server-23-rmapr-rpl2_nospw.sh expected/test-rmapr-rpl-out-nospw.pcap outdir/test-rmapr-rpl-out-nospw.pcap
do_test ./test-server2client-23-rmapr-rpl2_nospw.sh expected/test-rmapr-rpl-out-nospw.pcap outdir/test-rmapr-rpl-out-nospw.pcap

# case 22.
#               Initiator       network       Target
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP =+> RMAPRR/PCAP
#                                                SPP/PCAP =+

do_test ./test-client2server-22-rmapr-rpl.sh expected/test-rmapr-rpl-out.pcap outdir/test-rmapr-rpl-out.pcap
do_test ./test-server2client-22-rmapr-rpl.sh expected/test-rmapr-rpl-out.pcap outdir/test-rmapr-rpl-out.pcap

do_test ./test-client2server-22-rmapr-rpl_nospw.sh expected/test-rmapr-rpl-out-nospw.pcap outdir/test-rmapr-rpl-out-nospw.pcap
do_test ./test-server2client-22-rmapr-rpl_nospw.sh expected/test-rmapr-rpl-out-nospw.pcap outdir/test-rmapr-rpl-out-nospw.pcap

# case 21.
#               Initiator       network       Target
# xxx/PCAP => RMAPRD/PCAP => {RMAPRD/PCAP} => RMAPRD/PCAP

do_test ./test-client2server-21-rmapr.sh expected/test-rmapr-out.pcap outdir/test-rmapr-out.pcap
do_test ./test-server2client-21-rmapr.sh expected/test-rmapr-out.pcap outdir/test-rmapr-out.pcap

do_test ./test-client2server-21-rmapr_nospw.sh expected/test-rmapr-out-nospw.pcap outdir/test-rmapr-out-nospw.pcap
do_test ./test-server2client-21-rmapr_nospw.sh expected/test-rmapr-out-nospw.pcap outdir/test-rmapr-out-nospw.pcap

# case 15.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#  (check) <=     RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

echo ./test-client2server-15-rmapw-rpl3.sh 
./test-client2server-15-rmapw-rpl3.sh
echo ./test-server2client-15-rmapw-rpl3.sh 
./test-server2client-15-rmapw-rpl3.sh 

echo ./test-client2server-15-rmapw-rpl3_nospw.sh 
./test-client2server-15-rmapw-rpl3_nospw.sh
echo ./test-server2client-15-rmapw-rpl3_nospw.sh 
./test-server2client-15-rmapw-rpl3_nospw.sh 

# case 14.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP
#                 RMAPWR/PCAP <=     {RMAPWR/PCAP} <=     RMAPWR/PCAP

do_test ./test-client2server-14-rmapw-rpl2.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap
do_test ./test-server2client-14-rmapw-rpl2.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap

do_test ./test-client2server-14-rmapw-rpl2_nospw.sh expected/test-rpl-out-nospw.pcap outdir/test-rpl-out-nospw.pcap
do_test ./test-server2client-14-rmapw-rpl2_nospw.sh expected/test-rpl-out-nospw.pcap outdir/test-rpl-out-nospw.pcap

# case 13.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => RMAPWR/PCAP

do_test ./test-client2server-13-rmapw-rpl.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap
do_test ./test-server2client-13-rmapw-rpl.sh expected/test-rpl-out.pcap outdir/test-rpl-out.pcap

do_test ./test-client2server-13-rmapw-rpl_nospw.sh expected/test-rpl-out-nospw.pcap outdir/test-rpl-out-nospw.pcap
do_test ./test-server2client-13-rmapw-rpl_nospw.sh expected/test-rpl-out-nospw.pcap outdir/test-rpl-out-nospw.pcap

# case 12.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP => SPP/PCAP

do_test ./test-client2server-12-rmapw-spp.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap
do_test ./test-server2client-12-rmapw-spp.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap

do_test ./test-client2server-12-rmapw-spp_nospw.sh expected/test-spp-out.pcap outdir/test-spp-out-nospw.pcap
do_test ./test-server2client-12-rmapw-spp_nospw.sh expected/test-spp-out.pcap outdir/test-spp-out-nospw.pcap

# case 11.
#                   Initiator         network         Target
# SPP/PCAP => SPP/RMAPWC/PCAP => {SPP/RMAPWC/PCAP} => SPP/RMAPWC/PCAP

do_test ./test-client2server-11-rmapw.sh expected/test-rmapw-spp-out.pcap outdir/test-rmapw-spp-out.pcap
do_test ./test-server2client-11-rmapw.sh expected/test-rmapw-spp-out.pcap outdir/test-rmapw-spp-out.pcap

do_test ./test-client2server-11-rmapw_nospw.sh expected/test-rmapw-spp-out-nospw.pcap outdir/test-rmapw-spp-out-nospw.pcap
do_test ./test-server2client-11-rmapw_nospw.sh expected/test-rmapw-spp-out-nospw.pcap outdir/test-rmapw-spp-out-nospw.pcap

# case 1.
#                   Initiator         network         Target
#                    SPP/PCAP =>     {SPP/PCAP}    => SPP/PCAP

do_test ./test-client2server.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap
do_test ./test-server2client.sh expected/test-spp-out.pcap outdir/test-spp-out.pcap

# case delay of pcap-rmap-target
echo ./test-delay-all.sh
./test-delay-all.sh
if [ $? -ne 0 ]; then  
  echo test failed
  exit
fi

echo all test succeeded
