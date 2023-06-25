#!/usr/bin/env bash

progdir=`dirname $0`

args_nc=""
args_replay=""

while (( $# > 0 ))
do
    case $1 in
	# ...
	-a | --after | --after=*)
	    if [[ "$1" =~ ^--after= ]]; then
		OPT=$(echo $1 | sed -e 's/^--after=//')
	    elif [[ -z "$2" ]] || [[ "$2" =~ ^-+ ]]; then
		echo "'option --after' requires an argument." 1>&2
		exit 1
	    else
		OPT="$2"
		shift
	    fi
	    args_replay="$args_replay --after=$OPT"
	    ;;
	*)
	    args_nc="$args_nc $1"
	    
	    # TODO fix parameter with spaces
    esac
    shift
done
							    
# echo $args_nc
# echo $args_replay

$progdir/pcap-replay $args_replay | nc $args_nc | $progdir/pcap-store

# pass all arguments to nc
