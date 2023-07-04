#include "rmap_channel.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>

static class rmap_write_channel rmapw;

int main(int argc, char *argv[])
{
    rmapw.read_json("../test/sample.json", "channel1");

    ////

    printf("destination_path_address:    " );
    for ( size_t i=0 ; i<rmapw.num_dpa ; i++ ) printf("0x%02" PRIx8  " ", rmapw.d_path_address[i] ); fputc('\n', stdout);
    printf("destination_logical_address: 0x%02" PRIx8  "\n", rmapw.destination_logical_address );
    printf("destination_key:             0x%02" PRIx8  "\n", rmapw.destination_key );
    printf("source_path_address:         " );
    for ( size_t i=0 ; i<rmapw.num_spa ; i++ ) printf("0x%02" PRIx8  " ", rmapw.s_path_address[i] ); fputc('\n', stdout);
    printf("source_logical_address:      0x%02" PRIx8  "\n", rmapw.source_logical_address );
    printf("write_address:               0x%08" PRIx64 "\n", rmapw.write_address ); // nominally 64bits, maximum 80bits
    printf("\n");

    ////

    uint8_t  inbuf [10] = {0x12, 0x34, 0x56, 0x78, 0x9a,  0xFE, 0xDC, 0xBA, 0x98, 0x76};
    uint32_t insize     = sizeof(inbuf);
    uint8_t  sendbuf[999];
    size_t   sendsize   = sizeof(sendbuf);

    rmapw.send_witouht_ack(inbuf, insize, sendbuf, &sendsize);

    ////

    const size_t p = rmapw.num_dpa_padding;
    const size_t q = sendsize+p;

    printf("Transmitted RMAP Command:\n");
    for ( size_t i=0 ; i<q ; i++ ){
        if ( i < p ) printf("  ");
        else printf( "%02x", sendbuf[i-p]);
        if ( i%4==3 || i == q-1 ) printf("\n"); else printf(" ");
    }    
    fflush(stdout);

    ////

    const size_t num_path_address = rmap_num_path_address(sendbuf, sendsize);

    uint8_t *recvbuf  = sendbuf  + num_path_address;
    size_t   recvsize = sendsize - num_path_address;

    printf("Received RMAP Command:\n");
    for ( size_t i=0 ; i<recvsize ; i++ ){
        printf( "%02x", recvbuf[i]);
        if ( i%4==3 || i == recvsize-1 ) printf("\n"); else printf(" ");
    }    
    fflush(stdout);

    ////

    const uint8_t *outbuf;
    size_t         outsize;

    rmapw.recv(recvbuf, recvsize, &outbuf, &outsize);

    printf("Received Data:\n");
    for ( size_t i=0 ; i<outsize ; i++ ){
        printf( "%02x", outbuf[i]);
        if ( i == outsize-1 ) printf("\n"); else printf(" ");
    }    
    fflush(stdout);
}
