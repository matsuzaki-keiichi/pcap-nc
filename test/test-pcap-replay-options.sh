#!/bin/bash

function do_test(){
  echo $1
  $1 2>outdir/$2
  diff expected/$2 outdir
  if [ $? -ne 0 ]; then  
    echo test failed
    exit
  fi
  rm -f $3
}

rm -f outdir/test-pcap-replay-options*.log
mkdir -p outdir

CHANWO='--config=sample.json --channel=channel1'
CHANWR='--config=sample.json --channel=channel2'
CHANRD='--config=sample.json --channel=channel3'

do_test '../bin/pcap-replay --channel=name'                      test-pcap-replay-options1.log 
do_test '../bin/pcap-replay --config=sample.json --channel=xxxx' test-pcap-replay-options2.log 
do_test '../bin/pcap-replay --config=xxxxxx.json --channel=xxxx' test-pcap-replay-options3.log 
do_test '../bin/pcap-replay --config=errors.json --channel=xxxx' test-pcap-replay-options4.log 
do_test '../bin/pcap-replay --receive-reply=xxxxx'               test-pcap-replay-options5.log 
do_test "../bin/pcap-replay $CHANWO --receive-reply=xxxx"        test-pcap-replay-options6.log 
do_test "../bin/pcap-replay --store-data=xxxx"                   test-pcap-replay-options7.log 
do_test "../bin/pcap-replay $CHANWR --store-data=xxxx"           test-pcap-replay-options8.log 
do_test "../bin/pcap-replay $CHANRD --store-data=xxxx"           test-pcap-replay-options9.log 

echo all test succeeded

