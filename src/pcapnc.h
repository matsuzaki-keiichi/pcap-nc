#include <stdio.h>
#include <stdint.h>
#include <string>

#define pcapnc_logerr(...) fprintf(stderr, __VA_ARGS__)

#define PCAP_HEADER_SIZE    24
#define PACKET_HEADER_SIZE  16
#define PACKET_DATA_MAX_SIZE 0x10006

class pcapnc {
  public:
  uint32_t p2n;
  int exec_bswap;

  uint32_t coarse_time;
  uint32_t nanosec;
  uint32_t caplen;
  uint32_t orglen;

  private:
  size_t read(void *buf, size_t nmemb);
  size_t write(const void *buf, size_t nmemb);

  public:
  static void init_class(char *argv0);

  int read_nohead(FILE       *rp);
  int read_nohead(const char *filename);
  int read_head  (const char *filename);
  int read_head  (FILE       *rp);

  int write_nohead(FILE       *wp);
  int write_head  (const char *filename, uint8_t linktype);
  int write_head  (FILE       *wp,       uint8_t linktype);

  int read_packet_header(uint8_t record_buffer[], size_t buffer_size, const char *source_name);
  int read_packet_data  (uint8_t record_buffer[], const char *source_name);

  int write_packet_record(uint32_t coarse_time, uint32_t nanosec, uint8_t outot_buf[], const uint8_t outbuf[], size_t outlen, const char *source_name);
  inline int write_packet_record(uint32_t coarse_time, uint32_t nanosec, const uint8_t outbuf[], size_t outlen, const char *source_name){
    return this->write_packet_record(coarse_time, nanosec, NULL, outbuf, outlen, source_name);
  }

  uint16_t extract_uint16(void *ptr);
  uint32_t extract_uint32(void *ptr);

  private:
  FILE *rp;
  FILE *wp;

  static std::string _progname;
};
