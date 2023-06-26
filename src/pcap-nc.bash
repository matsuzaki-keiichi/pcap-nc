#!/usr/bin/env bash

progdir=`dirname $0`

args_nc=""
args_replay=""
args_store=""

while (( $# > 0 ))
do
    case $1 in
	--after |                          --after=*)
	    if [[ "$1" =~                 ^--after= ]]; then
		OPT=$(echo $1 | sed -e 's/^--after=//')
	    elif [[ -z "$2" ]] || [[ "$2" =~ ^-+ ]]; then
		echo              "'option --after' requires an argument." 1>&2
		exit 1
	    else
		OPT="$2"
		shift
	    fi
	    args_replay="$args_replay --after=$OPT"
	    ;;
	--interval |                       --interval=*)
	    if [[ "$1" =~                 ^--interval= ]]; then
		OPT=$(echo $1 | sed -e 's/^--interval=//')
	    elif [[ -z "$2" ]] || [[ "$2" =~ ^-+ ]]; then
		echo              "'option --interval' requires an argument." 1>&2
		exit 1
	    else
		OPT="$2"
		shift
	    fi
	    args_replay="$args_replay --interval=$OPT"
	    ;;
	--original-time)
	    args_replay="$args_replay --original-time"
	    ;;
	--link-type | --link-type=*)
	    if [[ "$1" =~ ^--link-type= ]]; then
		OPT=$(echo $1 | sed -e 's/^--link-type=//')
	    elif [[ -z "$2" ]] || [[ "$2" =~ ^-+ ]]; then
		echo "'option --link-type' requires an argument." 1>&2
		exit 1
	    else
		OPT="$2"
		shift
	    fi
	    case $OPT in
		diosatlm | spp | spw)
		;;
		*)
		    echo "'option --link-type' requires either diosatlm, spp, or spw." 1>&2
		    exit 1
	    esac
	    args_store="$arg_store --link-type=$OPT"
	    ;;
	*)
	    # pass all other arguments to nc
	    args_nc="$args_nc $1"
	    
	    # TODO fix parameter with spaces
    esac
    shift
done
							    
# echo $args_nc
# echo $args_replay
# echo args_store=$args_store

stdbuf -o 0 $progdir/pcap-replay $args_replay | stdbuf -i 0 -o 0 nc $args_nc | stdbuf -i 0 $progdir/pcap-store $args_store

