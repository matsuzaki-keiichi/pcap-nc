// spw_on_eth_head.h
#ifndef SPW_ON_ETH_HEAD_H
#define SPW_ON_ETH_HEAD_H

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#define SPW_ON_ETH_HEAD_SIZE 2
#define SPWONETHFLAG  0x00
#define SPWONETHRESERVE  0x00
#define pcapnc_logerr(...) fprintf(stderr, __VA_ARGS__)

class spw_on_eth_head {
public:
    static void insert_spw_on_eth_header(uint8_t* buffer, size_t &buffer_len);
    static int validate_remove_spw_on_eth_header(const uint8_t *&buffer, size_t &buffer_len);
};

#endif 
