#include "pcapnc.h"

#include <inttypes.h>
// PRIxN
#include <unistd.h>
// sleep
#include <arpa/inet.h>
// htonl
// ntohl
#include <byteswap.h>
// bswap_32 (gcc)
#include <string.h>
// memcpy
#include <stdio.h>
// setvbuf

// #define DEBUG

#define READ_RETRY  1 // sec
#define WRITE_RETRY 1 // sec

size_t pcapnc::read(void *buf, size_t nmemb){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;

  while ( remaining_nmemb > 0 ) {	    
    ret = fread(buf, 1, remaining_nmemb, this->rp);

    if ( ret > 0 ) {
      remaining_nmemb -= ret;
    } else {
      //fprintf(stderr, "remaining_nmemb=%zu\n", remaining_nmemb);
      if ( feof(this->rp) ) break;
      if ( ferror(this->rp) ) break;
      //fprintf(stderr, "sleep 1\n");
      sleep(READ_RETRY);
    }
  }
  return nmemb - remaining_nmemb;
}

size_t pcapnc::write(const void *buf, size_t nmemb){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;
  while ( remaining_nmemb > 0 ) {
    // debug_fprintf(stderr, "remaining_nmemb=%zu\n", remaining_nmemb);	    
    ret = fwrite(buf, 1, remaining_nmemb, this->wp);
    if ( ret > 0 ) {
      remaining_nmemb -= ret;
    } else {
      if ( feof(this->wp) ) break;
      if ( ferror(this->wp) ) break;
      sleep(WRITE_RETRY);
    }
  }
  return nmemb - remaining_nmemb;
}

uint32_t pcapnc_extract_uint32(int exec_bswap, void *ptr){
  const uint32_t value = * (uint32_t*) ptr;
  return (exec_bswap) ? bswap_32(value) : value;
}

uint16_t pcapnc_extract_uint16(int exec_bswap, void *ptr){
  const uint16_t value = * (uint16_t*) ptr;
  return (exec_bswap) ? bswap_16(value) : value;
}

void pcapnc_network_encode_uint32(void *ptr, uint32_t value){
  * (uint32_t*) ptr = htonl( value );
}

uint32_t pcapnc_network_decode_uint32(void *ptr){
  return ntohl( * (uint32_t*) ptr );
}

#define MAGIC_NUMBER_USEC   0xA1B2C3D4
#define MAGIC_NUMBER_NSEC   0xA1B23C4D
#define PCAP_MAJOR_VERSION   2
#define PCAP_MINOR_VERSION   4

#define ERROR_1 1
#define ERROR_2 2
#define ERROR_3 3
#define ERROR_4 4
#define ERROR_5 5
#define ERROR_6 6
#define ERROR_7 7

/**
 * @return 0:success, othewise fail.
*/

int pcapnc::read_nohead(FILE *rp){
  this->rp = rp;
  this->p2n = 1;   
  this->exec_bswap = 1; 

  const int ret = setvbuf(rp,  NULL, _IONBF, 0);
  if ( ret != 0 ) pcapnc_logerr("Failed to Unset input buffer.\n");

  return ret;
}

/**
 * @return 0:success, othewise fail.
*/

int pcapnc::read_nohead(const char *filename){
  FILE *rp = fopen(filename, "r");
  if ( rp == NULL ) {
    //// pcapnc_logerr("Input file (%s) open failed.\n", filename);
    return ERROR_5;
  }

  this->read_nohead(rp);
  return 0;
}  

/**
 * @return 0:success, othewise fail.
*/

int pcapnc::read_head(const char *filename){
  return this->read_nohead(filename) || this->read_head(this->rp);    
}

/**
 * @return 0:success, othewise fail.
*/

int pcapnc::read_head(FILE *rp){

  this->read_nohead(rp);

  uint8_t inbuf[PCAP_HEADER_SIZE];

  ssize_t ret = this->read(inbuf, PCAP_HEADER_SIZE);
  if ( ret == 0 ) {
    pcapnc_logerr("No input (missing header).\n");
    return ERROR_1;
  } else if ( ret < PCAP_HEADER_SIZE ) {
    pcapnc_logerr("File size smaller than the PCAP Header.\n");
    return ERROR_2;
  }

  const uint32_t magic_number = *(uint32_t*)&(inbuf[ 0]);
  const uint32_t magic_number_swap = bswap_32(magic_number);
  
  if      ( magic_number      == MAGIC_NUMBER_USEC ) { /* this->finetime_unit = 1e-6; */ this->p2n = 1000; this->exec_bswap = 0; }
  else if ( magic_number_swap == MAGIC_NUMBER_USEC ) { /* this->finetime_unit = 1e-6; */ this->p2n = 1000; this->exec_bswap = 1; }
  else if ( magic_number      == MAGIC_NUMBER_NSEC ) { /* this->finetime_unit = 1e-9; */ this->p2n = 1;    this->exec_bswap = 0; }
  else if ( magic_number_swap == MAGIC_NUMBER_NSEC ) { /* this->finetime_unit = 1e-9; */ this->p2n = 1;    this->exec_bswap = 1; }
  else {
    pcapnc_logerr("File is not a PCAP file (bad magic number).\n");
    return ERROR_3;
  }

  const uint32_t major_version = pcapnc_extract_uint16(exec_bswap, inbuf+4 );
  const uint32_t minor_version = pcapnc_extract_uint16(exec_bswap, inbuf+6 );

  if ( major_version != PCAP_MAJOR_VERSION || minor_version != PCAP_MINOR_VERSION ) {
    pcapnc_logerr("File is not a PCAP file (unexpected version number=%" PRId16 ".%" PRId16 ").\n",
	    major_version, minor_version);
    return ERROR_4;
  }
  return 0;
}

/**
 * @return 0:success, othewise fail.
*/

int pcapnc::write_nohead(FILE *wp){
  this->wp = wp;
  this->p2n = 1;
  this->exec_bswap = 0;

  const int ret = setvbuf(wp,  NULL, _IONBF, 0);
  if ( ret != 0 ) pcapnc_logerr("Failed to Unset output buffer.\n");
  return ret;
}

static uint8_t output_pcap_header[PCAP_HEADER_SIZE] = {
  0xA1, 0xB2, 0x3C, 0x4D, // Magic Number Nano Sec
  0x00, 0x02, 0x00, 0x04, // Major Version, Minor Version
  0x00, 0x00, 0x00, 0x09, // Time Zone
  0x00, 0x00, 0x00, 0x00, // Sigfig
  0x00, 0x01, 0x00, 0x12, // Scap Len
  0x00, 0x00, 0x00, 0x95  // Link Type (0x95=149: DLT_USER2 = SpaceWire)
};

/**
 * @return 0:success, othewise fail.
*/

int pcapnc::write_head(const char *filename, uint8_t linktype){
  FILE *wp = fopen(filename, "w");
  if ( wp == NULL ) {
    //// pcapnc_logerr("Output file (%s) open failed.\n", filename);
    return ERROR_5;
  }
  return this->write_head(wp, linktype);    
}

/**
 * @return 0:success, othewise fail.
*/

int pcapnc::write_head(FILE *wp, uint8_t linktype){
  this->write_nohead(wp);

  output_pcap_header[23] = linktype;
 
  ssize_t ret = this->write(output_pcap_header, PCAP_HEADER_SIZE);
  if ( ret < PCAP_HEADER_SIZE ) {
    pcapnc_logerr("Output error .\n");
    return ERROR_2;
  }
  return 0;
}

#define PACKET_HEADER_SIZE  16
// TODO eliminate duplicated definition

int pcapnc::read_packet_header(uint8_t record_buffer[], size_t buffer_size, const char *prog_name, const char *source_name){
  const size_t ret = this->read(record_buffer, PACKET_HEADER_SIZE);
  if        ( ret == 0 ) {
    return -1;
  } else if ( ret < PACKET_HEADER_SIZE ) {
    pcapnc_logerr("%sUnexpected end of %s (partial packet header).\n", prog_name, source_name);
    return ERROR_5;
  }

  this->coarse_time = this->extract_uint32(record_buffer+ 0);
  this->nanosec     = this->extract_uint32(record_buffer+ 4) * this->p2n;
  this->caplen      = this->extract_uint32(record_buffer+ 8);
  this->orglen      = this->extract_uint32(record_buffer+12);

  if ( PACKET_HEADER_SIZE + caplen > buffer_size ) {
    pcapnc_logerr("%sUnexpected packet header (caplen(=%" PRIx32 ") too long).\n", prog_name, this->caplen);
    return ERROR_6;
  }
  return 0;
}

int pcapnc::read_packet_data(uint8_t record_buffer[], const char *prog_name, const char *source_name){
  const size_t ret = this->read(&(record_buffer[PACKET_HEADER_SIZE]), this->caplen);
  if ( ret < this->caplen ) {
    pcapnc_logerr("%sUnexpected end of input (partial packet data).\n", prog_name);
    return ERROR_7;
  }
  return 0;
}

static uint8_t inner_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

/**
  @param coarse_time [in] the value of the coarse time field in the Packet Header
  @param nanosec     [in] the value of the nanosec field in the Packet Header
  @param outpt_buf   [in/out]
  Note: if this parameter is not NULL, Packet Data field in outpt_buf shall be set by user.
  Note: Packet Header in outpt_buf is updated by this method.
  @param outbuf      [in] content of Packet Data field
  Note: if this parameter is not NULL, Packet Data field is constructed by this method.
  Note: either outpt_bur or out_buf shall be NULL
  @param outlen      [in] length of Packet Data field
  @param prog_name   [in] might be used in Error Messages
  @param source_name [in] might be used in Error Messages
*/
int pcapnc::write_packet_record(uint32_t coarse_time, uint32_t nanosec, uint8_t outpt_buf[], const uint8_t outbuf[], size_t outlen, const char *prog_name, const char *source_name){

  uint8_t *const trans_buf = (outpt_buf == NULL) ? inner_buf : outpt_buf;

  pcapnc_network_encode_uint32(trans_buf+ 0, coarse_time);
  pcapnc_network_encode_uint32(trans_buf+ 4, nanosec);
  pcapnc_network_encode_uint32(trans_buf+ 8, outlen);
  pcapnc_network_encode_uint32(trans_buf+12, outlen);

  if (outpt_buf == NULL) {
    memcpy(trans_buf+PACKET_HEADER_SIZE, outbuf, outlen);
  }

  const size_t trans_len = PACKET_HEADER_SIZE + outlen;
  return this->write(trans_buf, trans_len);
}

uint16_t pcapnc::extract_uint16(void *ptr){
  const uint16_t value = * (uint16_t*) ptr;
  return (this->exec_bswap) ? bswap_16(value) : value;
}

uint32_t pcapnc::extract_uint32(void *ptr){
  const uint32_t value = * (uint32_t*) ptr;
  return (this->exec_bswap) ? bswap_32(value) : value;
}

