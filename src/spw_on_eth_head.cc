#include "spw_on_eth_head.h"
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>

#define pcapnc_logerr(...) fprintf(stderr, __VA_ARGS__) 
// Function to insert SpaceWire-on-Ethernet header
void spw_on_eth_head::insert_spw_on_eth_header(uint8_t* cmdbuf, size_t& cmdlen) {
    memmove(cmdbuf + 2, cmdbuf, cmdlen); // Move data 2 bytes forward
    cmdbuf[0] = SPWONETHFLAG;           // Insert flag
    cmdbuf[1] = SPWONETHRESERVE;        // Insert reserve byte
    cmdlen += 2;                        // Increase command length by 2 bytes
}

// Function to check the buffer's Flag
int spw_on_eth_head::validate_remove_spw_on_eth_header(const uint8_t *&tmpbuf, size_t& replen) {
    if (tmpbuf[0] != 0x00) {
        pcapnc_logerr("SpaceWire On Ethernet Flag is not 0x00 but 0x%02x.\n", 
            tmpbuf[0]);
        return -1; 
    } 
    tmpbuf += 2;    // Advance the pointer by 2 bytes
    replen -= 2;    // Decrease the buffer length by 2 bytes
    return 0;
    
}

