#include "rmap_channel.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>

static class rmap_write_channel rmapw;

int main(int argc, char *argv[])
{
    rmapw.read_json("../test/sample.json", "channel2");

    ////

    fprintf(stderr, "destination_path_address:    " );
    for ( size_t i=0 ; i<rmapw.num_dpa ; i++ ) fprintf(stderr, "0x%02" PRIx8  " ", rmapw.d_path_address[i] ); fputc('\n', stderr);
    fprintf(stderr, "destination_logical_address: 0x%02" PRIx8  "\n", rmapw.destination_logical_address );
    fprintf(stderr, "destination_key:             0x%02" PRIx8  "\n", rmapw.destination_key );
    fprintf(stderr, "source_path_address:         " );
    for ( size_t i=0 ; i<rmapw.num_spa ; i++ ) fprintf(stderr, "0x%02" PRIx8  " ", rmapw.s_path_address[i] ); fputc('\n', stderr);
    fprintf(stderr, "source_logical_address:      0x%02" PRIx8  "\n", rmapw.source_logical_address );
    fprintf(stderr, "memory_address:              0x%08" PRIx64 "\n", rmapw.memory_address ); // nominally 64bits, maximum 80bits
    fprintf(stderr, "\n");

    //// Generate and Transmit RMAP Write Command

    uint8_t  inbuf [10] = {0x12, 0x34, 0x56, 0x78, 0x9a,  0xFE, 0xDC, 0xBA, 0x98, 0x76};
    uint32_t insize     = sizeof(inbuf);
    uint8_t  sendbuf[999];
    size_t   sendsize   = sizeof(sendbuf);

    rmapw.send_witouht_ack(inbuf, insize, sendbuf, &sendsize);

    const size_t p = rmapw.num_dpa_padding;
    const size_t q = sendsize+p;

    fprintf(stderr, "Transmitted RMAP Command:\n");
    for ( size_t i=0 ; i<q ; i++ ){
        if ( i < p ) fprintf(stderr, "  ");
        else fprintf(stderr, "%02x", sendbuf[i-p]);
        if ( i%4==3 || i == q-1 ) fprintf(stderr, "\n"); else fprintf(stderr, " ");
    }    

    //// Receive RMAP Write Command

    const size_t num_recv_path_address = rmap_num_path_address(sendbuf, sendsize);

    uint8_t *recvbuf  = sendbuf  + num_recv_path_address;
    size_t   recvsize = sendsize - num_recv_path_address;

    fprintf(stderr, "Received RMAP Command:\n");
    for ( size_t i=0 ; i<recvsize ; i++ ){
        fprintf(stderr, "%02x", recvbuf[i]);
        if ( i%4==3 || i == recvsize-1 ) fprintf(stderr, "\n"); else fprintf(stderr, " ");
    }    

    //// Extract Service Data Unit from RMAP Write Command

    const uint8_t *outbuf;
    size_t         outsize = 0;

    rmapw.recv(recvbuf, recvsize, &outbuf, &outsize);

    fprintf(stderr, "Received Data (%zu):\n", outsize);
    for ( size_t i=0 ; i<outsize ; i++ ){
        fprintf(stderr, "%02x", outbuf[i]);
        if ( i == outsize-1 ) fprintf(stderr, "\n"); else fprintf(stderr, " ");
    }

    //// Generate and Transmit RMAP Write Reply

    uint8_t  replybuf[20];
    size_t   replysize   = sizeof(replybuf);

    rmapw.reply(recvbuf, recvsize, replybuf, &replysize);

    fprintf(stderr, "Transmitted RMAP Reply:\n");
    for ( size_t i=0 ; i<replysize ; i++ ){
        fprintf(stderr, "%02x", replybuf[i]);
        if ( i%4==3 || i == replysize-1 ) fprintf(stderr, "\n"); else fprintf(stderr, " ");
    }    

    //// Receive RMAP Write Reply

    const size_t num_retn_path_address = rmap_num_path_address(replybuf, replysize);

    uint8_t *retnbuf  = replybuf  + num_retn_path_address;
    size_t   retnsize = replysize - num_retn_path_address;

    fprintf(stderr, "Received RMAP Reply:\n");
    for ( size_t i=0 ; i<retnsize ; i++ ){
        fprintf(stderr, "%02x", retnbuf[i]);
        if ( i%4==3 || i == retnsize-1 ) fprintf(stderr, "\n"); else fprintf(stderr, " ");
    }    

    rmapw.recv_reply(retnbuf, retnsize);
}
