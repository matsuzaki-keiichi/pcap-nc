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

echo start of num-packet test

rm -f outdir/test-pcap-nc-num-packet*.log
mkdir -p outdir


#
# num-packet test 1
# argument test
#
# case error (invalid argument)
do_test_arg '../bin/pcap-replay --read-repeated --num-packet=XXX' test-pcap-replay-readrepeated1.log outdir/test-pcap-replay-readrepeated1.log

#
# num-packet test 2
# argument test
#
# case error (out of range)
do_test_arg '../bin/pcap-replay --read-repeated --num-packet=1.2e+4932' test-pcap-replay-readrepeated2.log outdir/test-pcap-replay-readrepeated2.log

#
# num-packet test 3
# argument test
#
# case error (only use)
do_test_arg '../bin/pcap-replay --num-packet=1' test-pcap-replay-readrepeated3.log outdir/test-pcap-replay-readrepeated3.log

#
# num-packet test 4
# argument test
#
# case error (miss match)
do_test_arg '../bin/pcap-replay --read-repeated --num-packet=1 --original-time' test-pcap-replay-readrepeated4.log outdir/test-pcap-replay-readrepeated4.log


#
# num-packet test 5
# argument test
#
# case error (miss match)
echo '../bin/pcap-replay --read-repeated < test-spp.pcap '
../bin/pcap-replay --read-repeated < test-spp.pcap 2> outdir/test-pcap-replay-readrepeated5.log
diff expected/test-pcap-replay-readrepeated5.log outdir
  if [ $? -ne 0 ]; then  
    echo test failed
    exit 1
  fi
  rm -f $3

echo all test succeeded
