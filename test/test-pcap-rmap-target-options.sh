#!/bin/bash

function do_test(){
  echo $1
  $1 2>outdir/$2
  diff expected/$2 outdir
  if [ $? -ne 0 ]; then  
    echo test failed
    exit 1
  fi
  rm -f $3
}

rm -f outdir/test-pcap-replay-options*.log
mkdir -p outdir

CHANWO='--config=sample.json --channel=channel1'
CHANWR='--config=sample.json --channel=channel2'
CHANRD='--config=sample.json --channel=channel3'

do_test '../bin/pcap-rmap-target'                                     test-pcap-rmap-target-options1.log
do_test '../bin/pcap-rmap-target --config=sample.json'                test-pcap-rmap-target-options2.log
do_test '../bin/pcap-rmap-target --config=xxxxxx.json --channel=xxxx' test-pcap-rmap-target-options3.log
do_test '../bin/pcap-rmap-target --config=errors.json --channel=xxxx' test-pcap-rmap-target-options4.log
do_test '../bin/pcap-rmap-target --config=sample.json --channel=xxxx' test-pcap-rmap-target-options5.log
do_test "../bin/pcap-rmap-target $CHANWR --send-data=xxxx"            test-pcap-rmap-target-options6.log
do_test "../bin/pcap-rmap-target $CHANRD --send-data=xxxx"            test-pcap-rmap-target-options7.log
do_test "../bin/pcap-rmap-target $CHANRD --store-data=xxxx"           test-pcap-rmap-target-options8.log
do_test "../bin/pcap-rmap-target $CHANWO --store-data=xx/xx"          test-pcap-rmap-target-options9.log

echo all test succeeded

