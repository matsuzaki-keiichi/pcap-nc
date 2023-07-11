#include "rmap_channel.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>

static void output_buffer(const uint8_t buffer[], size_t length, size_t leading_padding_length){
    size_t p = leading_padding_length;
    size_t q = length + p;

    for ( size_t i=0 ; i<q ; i++ ){
        if ( i < p ) fprintf(stderr, "  ");
        else fprintf(stderr, "%02x", buffer[i-p]);
        if ( i%4==3 || i == q-1 ) fprintf(stderr, "\n"); else fprintf(stderr, " ");
    }    
}

static void test_write_channel(){

    class rmap_channel rmapw;

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

    const uint8_t  inpbuf [10] = {0x12, 0x34, 0x56, 0x78, 0x9a,  0xFE, 0xDC, 0xBA, 0x98, 0x76};
    uint32_t inplen = sizeof(inpbuf);
    uint8_t  cmdbuf[999];
    size_t   cmdlen = sizeof(cmdbuf);

    rmapw.generate_write_command(inpbuf, inplen, cmdbuf, cmdlen);

    fprintf(stderr, "Transmitted RMAP Write Command:\n");
    output_buffer(cmdbuf, cmdlen, rmapw.num_dpa_padding);

    //// Receive RMAP Write Command

    const uint8_t *tmpbuf;
    tmpbuf = cmdbuf;
    rmap_channel::remove_path_address(tmpbuf, cmdlen);

    fprintf(stderr, "Received RMAP Write Command:\n");
    output_buffer(tmpbuf, cmdlen, 0);

    //// Extract Service Data Unit from RMAP Write Command

    const uint8_t *outbuf;
    size_t         outlen = 0;

    rmapw.validate_command(tmpbuf, cmdlen, outbuf, outlen);

    fprintf(stderr, "Received Data (%zu):\n", outlen);
    output_buffer(outbuf, outlen, 0);

    //// Generate and Transmit RMAP Write Reply

    uint8_t  rplbuf[20];
    size_t   rpllen = sizeof(rplbuf);

    rmapw.generate_write_reply(tmpbuf, cmdlen, rplbuf, rpllen);

    fprintf(stderr, "Transmitted RMAP Reply:\n");
    output_buffer(rplbuf, rpllen, 0);

    //// Receive RMAP Write Reply

    tmpbuf = rplbuf;
    rmap_channel::remove_path_address(tmpbuf, rpllen);

    fprintf(stderr, "Received RMAP Write Reply:\n");
    output_buffer(tmpbuf, rpllen, 0);

    const uint8_t *dmybuf = NULL;
    size_t dmylen=0;
    rmapw.validate_reply(tmpbuf, rpllen, dmybuf, dmylen);
}

void test_read_channel(){

    class rmap_channel rmapr;

    rmapr.read_json("../test/sample.json", "channel3");

    //// Generate and Transmit RMAP Read Command

    uint8_t cmdbuf[999];
    size_t  cmdlen = sizeof(cmdbuf);
    rmapr.generate_read_command(cmdbuf, cmdlen);
    fprintf(stderr, "Transmitted RMAP Read Command:\n");
    output_buffer(cmdbuf, cmdlen, rmapr.num_dpa_padding);

    //// Receive RMAP Read Command
    const uint8_t *tmpbuf = cmdbuf;
    rmap_channel::remove_path_address(tmpbuf, cmdlen);

    fprintf(stderr, "Received RMAP Read Command:\n");
    output_buffer(tmpbuf, cmdlen, 0);

    //// Generate and Transmit RMAP Read Reply

    const uint8_t  inpbuf [10] = {0x12, 0x34, 0x56, 0x78, 0x9a,  0xFE, 0xDC, 0xBA, 0x98, 0x76};
    const uint32_t inplen = sizeof(inpbuf);
    uint8_t  rplbuf[999];
    size_t   rpllen = sizeof(rplbuf);

    rmapr.generate_read_reply(inpbuf, inplen, tmpbuf, cmdlen, rplbuf, rpllen);

    fprintf(stderr, "Transmitted RMAP Read Reply:\n");
    output_buffer(rplbuf, rpllen, 0);

    //// Receive RMAP Write Reply
    const uint8_t *rtnbuf;
    size_t         rtnlen;
    tmpbuf = rplbuf;
    rmap_channel::remove_path_address(tmpbuf, rpllen);

    fprintf(stderr, "Received RMAP Read Reply:\n");
    output_buffer(tmpbuf, rpllen, 0);

    const uint8_t *outbuf = NULL;
    size_t outlen = 0;
    rmapr.validate_reply(tmpbuf, rpllen, outbuf, outlen);

    fprintf(stderr, "Received RMAP Read Reply Data:\n");
    output_buffer(outbuf, outlen, 0);
}

int main(int argc, char *argv[])
{
    fprintf(stderr, "Test RMAP Write Channel ----\n");
    test_write_channel();
    fprintf(stderr, "\n");
    fprintf(stderr, "Test RMAP Read Channel ----\n");
    test_read_channel();
    fprintf(stderr, "\n");
}
