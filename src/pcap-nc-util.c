#include "pcap-nc-util.h"

#include <inttypes.h>
// PRIxN
#include <unistd.h>
// sleep
#include <arpa/inet.h>
// htonl
// ntohl
#include <byteswap.h>
// bswap_32 (gcc)
#include <stdio.h>
// setvbuf

// #define DEBUG

#define READ_RETRY  1 // sec
#define WRITE_RETRY 1 // sec

void pcapnc_unset_stdbuf(){
  int ret;
  ret = setvbuf(stdin,  NULL, _IONBF, 0);
  if ( ret != 0 ) pcapnc_logerr("Failed to Unset stdin buffer.\n");

  ret = setvbuf(stdout, NULL, _IONBF, 0);
  if ( ret != 0 ) pcapnc_logerr("Failed to Unset stdout buffer.\n");
}

size_t pcap_file::read(void *buf, size_t size, size_t nmemb){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;

  while ( remaining_nmemb > 0 ) {	    
    ret = fread(buf, size, remaining_nmemb, this->rp);

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

size_t pcap_file::write(const void *buf, size_t size, size_t nmemb){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;
  while ( remaining_nmemb > 0 ) {
    // debug_fprintf(stderr, "remaining_nmemb=%zu\n", remaining_nmemb);	    
    ret = fwrite(buf, size, remaining_nmemb, this->wp);
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

size_t pcapnc_fwrite(const void *buf, size_t size, size_t nmemb, FILE *fp){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;

  while ( remaining_nmemb > 0 ) {
    // debug_fprintf(stderr, "remaining_nmemb=%zu\n", remaining_nmemb);
	    
    ret = fwrite(buf, size, remaining_nmemb, fp);

    if ( ret > 0 ) {
      remaining_nmemb -= ret;
    } else {
      if ( feof(fp) ) break;
      if ( ferror(fp) ) break;
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

int pcap_file::read_nohead(FILE *input){
  this->rp = input;
  this->p2n = 1;   
  this->exec_bswap = 1; 
  return 0;
}

int pcap_file::read_head(FILE *input){

  this->rp = input;

  uint8_t inbuf[PCAP_HEADER_SIZE];

  ssize_t ret = this->read(inbuf, 1, PCAP_HEADER_SIZE);
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

static uint8_t output_pcap_header[PCAP_HEADER_SIZE] = {
  0xA1, 0xB2, 0x3C, 0x4D, // Magic Number Nano Sec
  0x00, 0x02, 0x00, 0x04, // Major Version, Minor Version
  0x00, 0x00, 0x00, 0x09, // Time Zone
  0x00, 0x00, 0x00, 0x00, // Sigfig
  0x00, 0x01, 0x00, 0x12, // Scap Len
  0x00, 0x00, 0x00, 0x95  // Link Type (0x95=149: DLT_USER2 = SpaceWire)
};

int pcap_file::write_head(FILE *output, uint8_t linktype){
  this->wp = output;

  output_pcap_header[23] = linktype;
 
  ssize_t ret = this->write(output_pcap_header, 1, PCAP_HEADER_SIZE);
  if ( ret < PCAP_HEADER_SIZE ) {
    pcapnc_logerr("Output error .\n");
    return ERROR_2;
  }
  return 0;
}

int pcap_file::read_nohead(const char *filename){
  FILE *rp = fopen(filename, "r");
  if ( rp == NULL ) {
    pcapnc_logerr("Input file (%s) open failed.\n", filename);
    return ERROR_5;
  }

  const int ret = setvbuf(rp,  NULL, _IONBF, 0);
  if ( ret != 0 ) pcapnc_logerr("Failed to Unset input buffer.\n");

  return pcap_file::read_nohead(rp);    
}  

int pcap_file::read_head(const char *filename){
  return pcap_file::read_nohead(filename) || pcap_file::read_head(this->rp);    
}

int pcap_file::write_head(const char *filename, uint8_t linktype){
  FILE *wp = fopen(filename, "w");
  if ( wp == NULL ) {
    pcapnc_logerr("Output file (%s) open failed.\n", filename);
    return ERROR_5;
  }

  const int ret = setvbuf(wp,  NULL, _IONBF, 0);
  if ( ret != 0 ) pcapnc_logerr("Failed to Unset output buffer.\n");

  return pcap_file::write_head(wp, linktype);    
}

#define ERROR_5 5
#define ERROR_6 6
#define ERROR_7 7

#define PACKET_HEADER_SIZE  16
// TODO eliminate duplicated definition

int pcap_file::read_packet_header(uint8_t record_buffer[], size_t buffer_size, const char *prog_name, const char *source_name){
  const size_t ret = this->read(record_buffer, 1, PACKET_HEADER_SIZE);
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

int pcap_file::read_packet_data(uint8_t record_buffer[], const char *prog_name, const char *source_name){
  const size_t ret = this->read(&(record_buffer[PACKET_HEADER_SIZE]), 1, this->caplen);
  if ( ret < this->caplen ) {
    pcapnc_logerr("%sUnexpected end of input (partial packet data).\n", prog_name);
    return ERROR_7;
  }
  return 0;
}

uint16_t pcap_file::extract_uint16(void *ptr){
  const uint16_t value = * (uint16_t*) ptr;
  return (this->exec_bswap) ? bswap_16(value) : value;
}

uint32_t pcap_file::extract_uint32(void *ptr){
  const uint32_t value = * (uint32_t*) ptr;
  return (this->exec_bswap) ? bswap_32(value) : value;
}

