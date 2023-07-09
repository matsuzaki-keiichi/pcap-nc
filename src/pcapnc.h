#include <stdio.h>
#include <stdint.h>
#include <string>

#define pcapnc_logerr(...) fprintf(stderr, __VA_ARGS__)

#define PCAP_HEADER_SIZE    24
#define PACKET_HEADER_SIZE  16
#define PACKET_DATA_MAX_SIZE 0x10006

class pcapnc {
  public:
  uint32_t _p2n;
  int      _exec_bswap;

  uint32_t _coarse_time;
  uint32_t _nanosec;
  uint32_t _caplen;
  uint32_t _orglen;

  private:
  size_t read(void *buf, size_t nmemb);
  size_t write(const void *buf, size_t nmemb);

  public:
  static void init_class(char *argv0);

  /*
    @param time_mode   [in] either 0 or 1 
    1 means simulation time is replaced with the time value in Packet Header in the read_packet_header method
      and output time is replaced with current conputation time in write_packet_record method
    0 means the time value in Packet Header in the read_packet_header method is ignored
      and output time is simulation time
    @param source_name [in] soure_name to be appeared in error log
   */
  pcapnc(int time_mode, const char *source_name) { _time_mode = time_mode; _source_name = source_name; }

  int read_nohead(FILE       *rp);
  int read_nohead(const char *filename);
  int read_head  (const char *filename);
  int read_head  (FILE       *rp);

  int write_nohead(FILE       *wp);
  int write_head  (const char *filename, uint8_t linktype);
  int write_head  (FILE       *wp,       uint8_t linktype);
private:
  int read_packet_header();
  int read_packet_data(uint8_t inp_buf[], size_t inp_len);

public:
  int read_packet(uint8_t inp_buf[], size_t inp_len);
  int write_packet_record(uint8_t outot_buf[], const uint8_t outbuf[], size_t outlen);
  inline int write_packet_record(const uint8_t outbuf[], size_t outlen){
    return this->write_packet_record(NULL, outbuf, outlen);
  }

  uint16_t extract_uint16(void *ptr);
  uint32_t extract_uint32(void *ptr);

  private:
  FILE *_rp;
  FILE *_wp;
  int   _time_mode;
  const char *_source_name;

  static std::string _progname;
};
