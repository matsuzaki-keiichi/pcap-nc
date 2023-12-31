#include "pcapnc.h"

#include <stdio.h>
// setvbuf
#include <inttypes.h>
// PRIxN
#include <string.h>
// memcpy
#include <arpa/inet.h>
// htonl, ntohl
#include <byteswap.h>
// bswap_32 (gcc)
#include <sys/time.h>
// gettimeofday
#include <unistd.h>
// sleep

#include "s3sim.h"

static std::string _pcapnc_basename(const std::string& path) {
    return path.substr(path.find_last_of('/') + 1);
}

std::string pcapnc::_progname;

void pcapnc::init_class(char *argv0){
  _progname = _pcapnc_basename(std::string(argv0));  
}

// #define DEBUG

#define READ_RETRY  1 // sec
#define WRITE_RETRY 1 // sec

size_t pcapnc::read(void *buf, size_t nmemb){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;

  while ( remaining_nmemb > 0 ) {	    
    ret = fread(buf, 1, remaining_nmemb, this->_rp);

    if ( ret > 0 ) {
      remaining_nmemb -= ret;
    } else {
      if ( feof(this->_rp) ) break;
      if ( ferror(this->_rp) ) break;
      sleep(READ_RETRY);
    }
  }
  return nmemb - remaining_nmemb;
}

size_t pcapnc::write(const void *buf, size_t nmemb) const {
  size_t remaining_nmemb = nmemb;
  ssize_t ret;
  while ( remaining_nmemb > 0 ) {
    // debug_fprintf(stderr, "remaining_nmemb=%zu\n", remaining_nmemb);	    
    ret = fwrite(buf, 1, remaining_nmemb, this->_wp);
    if ( ret > 0 ) {
      remaining_nmemb -= ret;
    } else {
      if ( feof(this->_wp) ) break;
      if ( ferror(this->_wp) ) break;
      sleep(WRITE_RETRY);
    }
  }
  return nmemb - remaining_nmemb;
}

uint16_t pcapnc::extract_uint16(void *ptr){
  const uint16_t value = * (uint16_t*) ptr;
  return (this->_exec_bswap) ? bswap_16(value) : value;
}

uint32_t pcapnc::extract_uint32(void *ptr){
  const uint32_t value = * (uint32_t*) ptr;
  return (this->_exec_bswap) ? bswap_32(value) : value;
}

static void pcapnc_network_encode_uint32(void *ptr, uint32_t value){
  * (uint32_t*) ptr = htonl( value );
}

#define MAGIC_NUMBER_USEC   0xA1B2C3D4
#define MAGIC_NUMBER_NSEC   0xA1B23C4D
#define PCAP_MAJOR_VERSION   2
#define PCAP_MINOR_VERSION   4

#define ERROR_PARAM     11
#define ERROR_LOG_WARN  12
#define ERROR_LOG_FATAL 13

/**
  @return 0:success or ERROR_LOG_WARN.
*/
int pcapnc::read_nohead(FILE *rp){
  this->_rp = rp;
  this->_p2n = 1;   
  this->_exec_bswap = 1; 

  const int ret = setvbuf(rp, NULL, _IONBF, 0);
  if ( ret != 0 ) {
    pcapnc_logerr("%s: Failed to Unset %s buffer.\n", 
                   pcapnc::_progname.c_str(), this->_source_name );
    return ERROR_LOG_WARN;
  }
  return 0;
}

/**
  @return 0:success, ERROR_PARAM, or ERROR_LOG_WARN.
*/
int pcapnc::read_nohead(const char *filename){
  FILE *rp = fopen(filename, "r");
  if ( rp == NULL ) { return ERROR_PARAM; }

  this->read_nohead(rp);
  return 0;
}  

/**
  @return 0:success, ERROR_PARAM, ERROR_LOG_FATAL, or ERROR_LOG_WARN.
*/
int pcapnc::read_head(const char *filename){
  return this->read_nohead(filename) || this->read_head(this->_rp);    
}

/**
  @return 0:success, or ERROR_LOG_FATAL.
*/
int pcapnc::read_head(FILE *rp){

  this->read_nohead(rp);

  uint8_t inbuf[PCAP_HEADER_SIZE];

  ssize_t ret = this->read(inbuf, PCAP_HEADER_SIZE);
  if ( ret == 0 ) {
    pcapnc_logerr("%s: No input (missing header).\n", pcapnc::_progname.c_str());
    return ERROR_LOG_FATAL;
  } else if ( ret < PCAP_HEADER_SIZE ) {
    pcapnc_logerr("%s: File size smaller than the PCAP Header.\n", pcapnc::_progname.c_str());
    return ERROR_LOG_FATAL;
  }

  const uint32_t magic_number = *(uint32_t*)&(inbuf[ 0]);
  const uint32_t magic_number_swap = bswap_32(magic_number);
  
  if      ( magic_number      == MAGIC_NUMBER_USEC ) { /* this->finetime_unit = 1e-6; */ this->_p2n = 1000; this->_exec_bswap = 0; }
  else if ( magic_number_swap == MAGIC_NUMBER_USEC ) { /* this->finetime_unit = 1e-6; */ this->_p2n = 1000; this->_exec_bswap = 1; }
  else if ( magic_number      == MAGIC_NUMBER_NSEC ) { /* this->finetime_unit = 1e-9; */ this->_p2n = 1;    this->_exec_bswap = 0; }
  else if ( magic_number_swap == MAGIC_NUMBER_NSEC ) { /* this->finetime_unit = 1e-9; */ this->_p2n = 1;    this->_exec_bswap = 1; }
  else {
    pcapnc_logerr("%s: File is not a PCAP file (bad magic number).\n", pcapnc::_progname.c_str());
    return ERROR_LOG_FATAL;
  }

  const uint32_t major_version = this->extract_uint16(inbuf+4);
  const uint32_t minor_version = this->extract_uint16(inbuf+6);

  if ( major_version != PCAP_MAJOR_VERSION || minor_version != PCAP_MINOR_VERSION ) {
    pcapnc_logerr("%s: File is not a PCAP file (unexpected version number=%" PRId16 ".%" PRId16 ", ).\n",
	    pcapnc::_progname.c_str(), major_version, minor_version);
    return ERROR_LOG_FATAL;
  }
  return 0;
}

/**
  @return 0:success or ERROR_LOG_WARN.
*/
int pcapnc::write_nohead(FILE *wp){
  this->_wp = wp;
  this->_p2n = 1;
  this->_exec_bswap = 0;

  const int ret = setvbuf(wp,  NULL, _IONBF, 0);
  if ( ret != 0 ){
    pcapnc_logerr("%s: Failed to Unset %s buffer.\n", 
                   pcapnc::_progname.c_str(), this->_source_name );
    return ERROR_LOG_WARN;
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

/**
  @return 0:success, ERROR_PARAM, ERROR_LOG_FATAL, or ERROR_LOG_WARN.
*/
int pcapnc::write_head(const char *filename, uint8_t linktype){
  FILE *wp = fopen(filename, "w");
  if ( wp == NULL ) { return ERROR_PARAM; }
  return this->write_head(wp, linktype);    
}

/**
  @return 0:success, ERROR_LOG_FATAL, or ERROR_LOG_WARN.
*/
int pcapnc::write_head(FILE *wp, uint8_t linktype){
  this->write_nohead(wp);

  output_pcap_header[23] = linktype;
 
  ssize_t ret = this->write(output_pcap_header, PCAP_HEADER_SIZE);
  if ( ret < PCAP_HEADER_SIZE ) {
    pcapnc_logerr("%s: Output error .\n", pcapnc::_progname.c_str());
    return ERROR_LOG_FATAL;
  }
  return 0;
}

/**
  @return 0:success, -1:end of input, or ERROR_LOG_FATAL.
*/
int pcapnc::read_packet_header(){
  uint8_t header_buffer[PACKET_HEADER_SIZE];

  const size_t ret = this->read(header_buffer, PACKET_HEADER_SIZE);
  if        ( ret == 0 ) {
    return -1;
  } else if ( ret < PACKET_HEADER_SIZE ) {
    pcapnc_logerr("%s: Unexpected end of %s (partial packet header).\n", 
                   pcapnc::_progname.c_str(), this->_source_name);
    return ERROR_LOG_FATAL;
  }

  this->_coarse_time = this->extract_uint32(header_buffer+ 0);
  this->_nanosec     = this->extract_uint32(header_buffer+ 4) * this->_p2n;
  this->_caplen      = this->extract_uint32(header_buffer+ 8);
  this->_orglen      = this->extract_uint32(header_buffer+12);

  if ( this->_time_mode != 0 ){
    s3sim_coarse_time = this->_coarse_time;
    s3sim_nanosec     = this->_nanosec;
  }

  return 0;
}

/**
  @param inp_buf [in] buffer for a PCAP packet
  @param inp_len [in] size of the buffer
  @return 0:success or ERROR_LOG_FATAL.
*/
int pcapnc::read_packet_data(uint8_t inpbuf[], size_t inplen){
  if ( this->_caplen > inplen ) {
    pcapnc_logerr("%s: Unexpected packet header (caplen(=%" PRIx32 ") too long).\n", 
                   pcapnc::_progname.c_str(), this->_caplen);
    return ERROR_LOG_FATAL;
  }

  const size_t ret = this->read(inpbuf, this->_caplen);
  if ( ret < this->_caplen ) {
    pcapnc_logerr("%s: Unexpected end of input (partial packet data).\n", 
                   pcapnc::_progname.c_str());
    return ERROR_LOG_FATAL;
  }
  return 0;
}

/**
  @param inpbuf [in] buffer of record
  @param inplen [in] size of recorde_buffer, should be equal or larger than the record size
  @return 0:success, -1:end of input, or ERROR_LOG_FATAL.
*/
int pcapnc::read_packet(uint8_t inpbuf[], size_t inplen){
    int ret;
    ret = this->read_packet_header(); // 0:success, -1:end of input, or ERROR_LOG_FATAL
    if ( ret != 0 ) return ret;
    ret = this->read_packet_data(inpbuf, inplen); // 0:success or ERROR_LOG_FATAL.
    return ret;
}

static uint8_t inner_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

/**
  @param outbuf      [in] Packet Data
  Note: Packet Data field is copied by this method into the internal buffer.
  @param outlen      [in] length of Packet Data field
  @return 0:success or ERROR_LOG_FATAL.
*/
int pcapnc::write_packet(const uint8_t outbuf[], size_t outlen) const {

  uint8_t *const outpt_buf = inner_buf;

  if ( outlen > PACKET_DATA_MAX_SIZE ) {
    pcapnc_logerr("%s: Too large packet size for %s (=0x%zu)).\n", 
                   pcapnc::_progname.c_str(), this->_source_name, outlen);
    return ERROR_LOG_FATAL;
  }
  memcpy(outpt_buf+PACKET_HEADER_SIZE, outbuf, outlen);
  
  return this->write_packet_record(outpt_buf, outlen);
}

/**
  @param outpt_buf   [in/out] Buffer for PCAP Reacord (i.e. Packet Header + Packet Data)
  Note: Packet Data field in outpt_buf shall be set by user, which minimizes number of copy. 
  Note: Packet Header in outpt_buf is updated by this method.
  @param outlen      [in] length of Packet Data field
  @return 0:success or ERROR_LOG_FATAL.
*/

int pcapnc::write_packet_record(uint8_t outpt_buf[], size_t outlen) const {
  uint32_t coarse_time;
  uint32_t nanosec;

  if ( this->_time_mode == 0 ){
    coarse_time = s3sim_coarse_time;
    nanosec     = s3sim_nanosec;
  } else {
    struct timeval tv;      
    const int iret = gettimeofday(&tv, NULL);
    if ( iret == 0 ) {
     	coarse_time =        (uint32_t) tv.tv_sec;
     	nanosec     = 1000 * (uint32_t) tv.tv_usec;	
    } else {
      pcapnc_logerr("%s: error in gettime of day.\n", pcapnc::_progname.c_str()); // i.e. ERROR_LOG_WARN
      coarse_time = s3sim_coarse_time;
      nanosec     = s3sim_nanosec;
    }
  }

  pcapnc_network_encode_uint32(outpt_buf+ 0, coarse_time);
  pcapnc_network_encode_uint32(outpt_buf+ 4, nanosec);
  pcapnc_network_encode_uint32(outpt_buf+ 8, outlen);
  pcapnc_network_encode_uint32(outpt_buf+12, outlen);

  const size_t outpt_len = PACKET_HEADER_SIZE + outlen;
  const size_t reslt_len = this->write(outpt_buf, outpt_len);
  if ( reslt_len != outpt_len ) {
    pcapnc_logerr("%s: Fails to output '%s' (partial packet data).\n", 
                   pcapnc::_progname.c_str(), this->_source_name);
    return ERROR_LOG_FATAL;
  }
  return 0;
}
