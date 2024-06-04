#!/bin/bash

function do_test_arg(){
  echo $1
  $1 2> outdir/$2
  diff expected/$2 outdir
  if [ $? -ne 0 ]; then  
    echo test failed
    exit 1
  fi
  rm -f $3
}

function do_test(){
  echo $1
  $1
  diff $2 $3
  if [ $? -ne 0 ]; then  
    echo test failed
    exit 1
  fi
  rm -f $3
}

echo start of delay test

rm -f outdir/test-pcap-rmap-target-delay*.log
mkdir -p outdir


#
# Delay test 1
# argument test
#
# case error (invalid argument)
do_test_arg '../bin/pcap-rmap-target --config=sample.json --channel=channel1 --delay=XXX' test-pcap-rmap-target-delay1.log outdir/test-pcap-rmap-target-delay1.log

#
# Delay test 2
# argument test
#
# case error (out of range)
do_test_arg '../bin/pcap-rmap-target --config=sample.json --channel=channel1 --delay=1.2e+4932' test-pcap-rmap-target-delay2.log outdir/test-pcap-rmap-target-delay2.log

#
# Delay test 3.
#
# client to server RMAP Read with delay
#
do_test ./test-delay3.sh expected/test-rmapr-rpl-out-delay.pcap outdir/test-rmapr-rpl-out-delay.pcap

#
# Delay test 4.
#
# client to server RMAP Write with reply with delay
#
do_test ./test-delay4.sh expected/test-rpl-out-delay.pcap outdir/test-rpl-out-delay.pcap

#
# Delay test 5.
#
# server to client RMAP Read with delay
#
do_test ./test-delay5.sh expected/test-rmapr-rpl-out-delay.pcap outdir/test-rmapr-rpl-out-delay.pcap

#
# Delay test 6.
#
# server to client RMAP Write with reply with delay
#
do_test ./test-delay6.sh expected/test-rpl-out-delay.pcap outdir/test-rpl-out-delay.pcap


echo all test succeeded
