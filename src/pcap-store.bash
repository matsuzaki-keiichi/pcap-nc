#!/usr/bin/env bash

progdir=`dirname $0`

linktype=spw

while (( $# > 0 ))
do
    case $1 in
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
	    linktype="$OPT"
	    ;;
	*)
	    echo "unknown option '$1'." 1>&2
	    exit 1
    esac
    shift
done

stdbuf -i 0 -o 0 cat $progdir/head-$linktype.pcap -
							    
