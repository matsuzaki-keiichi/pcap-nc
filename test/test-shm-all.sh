#!/bin/bash
CHAN='--config=sample.json --channel=channel1'

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

echo start of shared memory test

rm -f outdir/test-pcap-rmap-target-shared-memory*.log
mkdir -p outdir

#
# shared memory test 1-1.
#
# argument test
#
# case error (invalid argument)
do_test_arg ./test-shm1-1.sh test-rmap-target-shm1.log outdir/test-rmap-target-shm1.log

#
# shared memory test 1-2.
#
# argument test
#
# case error (invalid argument)
do_test_arg ./test-shm1-2.sh test-rmap-target-shm2.log outdir/test-rmap-target-shm2.log

#
# shared memory test 1-3.
#
# argument test
#
# case error (invalid argument)
do_test_arg ./test-shm1-3.sh test-rmap-target-shm3.log outdir/test-rmap-target-shm3.log

#
# shared memory test 1-4.
#
# argument test
#
# case error (invalid argument)
do_test_arg ./test-shm1-4.sh test-rmap-target-shm4.log outdir/test-rmap-target-shm4.log

#
# shared memory test 1-5.
#
# argument test
#
# case error (invalid argument)
do_test_arg ./test-shm1-5.sh test-rmap-target-shm5.log outdir/test-rmap-target-shm5.log

#
# shared memory test 1-6.
#
# argument test
#
# case error (invalid argument)
do_test_arg ./test-shm1-6.sh test-rmap-target-shm6.log outdir/test-rmap-target-shm6.log

#
# shared memory test 1-7.
#
# argument test
#
# case error (invalid argument)
do_test_arg ./test-shm1-7.sh test-rmap-target-shm7.log outdir/test-rmap-target-shm7.log

#
# shared memory test 2-1.
#
# Write to shared memory
#
echo ./test-shm2-1.sh
./test-shm2-1.sh

#
# shared memory test 2-2.
#
# Read from shared memory
#
do_test ./test-shm2-2.sh expected/test-rmapr-rpl-out-shm.pcap outdir/test-rmapr-rpl-out-shm.pcap




echo all test succeeded