#include <getopt.h>
#include <string>
#include <stdlib.h>
// atof

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
// PRIx32

#include <unistd.h>
// sleep

#include "rmap_channel.h"
#include "pcapnc.h"
#include "s3sim.h"

// #define DEBUG

#ifdef DEBUG
#define debug_fprintf fprintf
#else
#define debug_fprintf
#endif

static int use_rmap_channel = 0;
static int use_rmap_reply   = 0;
static int store_rmap_read  = 0;

static double      param_after_wtime    =  0.0;
static double      param_before_wtime   =  0.0;
static double      param_interval_sec   = -1.0;
static std::string param_config         =  ""; 
static std::string param_channel        =  ""; 
static std::string param_reply_filename =  ""; 
static std::string param_store_filename =  ""; 
static int         param_original_time  =  0;

#define OPTSTRING ""

static struct option long_options[] = {
  {"after",         required_argument, NULL, 'a'},
  {"before",        required_argument, NULL, 'b'},
  {"config",        required_argument, NULL, 'c'},
  {"channel",       required_argument, NULL, 'n'},
  {"interval",      required_argument, NULL, 'i'},
  {"original-time",       no_argument, NULL, 'o'},
  {"receive-reply", required_argument, NULL, 'r'},
  {"store-data",    required_argument, NULL, 't'},
  { NULL,                           0, NULL,  0 }
};

#define PROGNAME "pcap-replay: "

#define ERROR_OPT 1
#define ERROR_RUN 2

int pcap_ptp_send_record(pcapnc &wp, uint8_t record_buf[], size_t packet_len){
  return wp.write_packet_record(record_buf, packet_len); // 0:success or ERROR_LOG_FATAL.
}

// inplen = (size_t) lp._caplen

int pcap_rmap_xxxx(class rmap_channel &rmapc, uint8_t inpbuf[], size_t inplen, const uint8_t *&outbuf, size_t &outlen){
  // simulate network
  const uint8_t *retbuf; size_t retlen;
  rmap_channel::remove_path_address(inpbuf, inplen, retbuf, retlen);
 
#if 0
fprintf(stderr,"inplen=%zu\n", retlen);
for(size_t i=0; i<retlen; i++) fprintf(stderr, "%02x ", retbuf[i]);
fprintf(stderr,"\n");
#endif
  rmapc.validate_reply(retbuf, retlen, outbuf, outlen); // extract Service Data Unit (e.g. Space Packet) for RMAP Read Reply
#if 0
fprintf(stderr,"outlen=%zu\n", outlen);
for(size_t i=0; i<outlen; i++) fprintf(stderr, "%02x ", outbuf[i]);
fprintf(stderr,"\n");
#endif
  return 0;
}

int pcap_rmapw_send(class rmap_channel &rmapc, pcapnc &wp, pcapnc &lp, uint8_t inpbuf[], size_t inplen){
  int ret;

  static uint8_t trans_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  uint8_t       *cmdbuf = trans_buf + PACKET_HEADER_SIZE;
  size_t         cmdlen = PACKET_DATA_MAX_SIZE;
  if ( rmapc.is_write_channel() ){
    // @ test-?????2?????-1*
    ret =
    rmapc.generate_write_command(inpbuf, inplen, cmdbuf, cmdlen); // 0:success or ERROR_LOG_FATAL.
    if ( ret != 0 ) return ERROR_RUN;      
  } else {
    // @ test-?????2?????-2*
    rmapc.generate_read_command(                 cmdbuf, cmdlen);
  }
  ret = wp.write_packet_record(trans_buf, cmdlen); // 0:success or ERROR_LOG_FATAL.
  if ( ret != 0 ) return ERROR_RUN;

  if ( use_rmap_reply ) {

    // reuse - input_buf ... TODO buffer size should not be hard codede     
    ret = lp.read_packet(inpbuf, PACKET_DATA_MAX_SIZE); // 0:success, -1:end of input, or ERROR_LOG_FATAL
    if ( ret <  0 ) { // end of input, without logging message
      // handle option '--after wait_sec' @ test-?????2?????-{14,15,23,24}*
      s3sim_sleep(param_after_wtime); 
      return 0; 
    }
    if ( ret >  0 ) return ERROR_RUN; 
    inplen = lp._caplen;

    // check returned packet is expected

    if ( rmapc.is_read_channel() && store_rmap_read ){
      // do nothing
    } else {
      const uint8_t *outbuf; size_t outlen;
      pcap_rmap_xxxx(rmapc, inpbuf, inplen, outbuf, outlen);
    }
  }
  return 0;
}

int pcap_rmapr_recv_record(class rmap_channel &rmapc, pcapnc &wp, pcapnc &lp, pcapnc &sp, uint8_t inpbuf[], size_t inplen, const uint8_t *&outbuf, size_t &outlen ){
  int ret = pcap_rmapw_send(rmapc, wp, lp, inpbuf, inplen);
  if ( ret != 0 ) return ERROR_RUN;

  if ( use_rmap_reply ) {
    if ( rmapc.is_read_channel() && store_rmap_read ){
    inplen = lp._caplen;
#if 0    
fprintf(stderr,"inplen=%zu\n", inplen);
for(size_t i=0; i<inplen; i++) fprintf(stderr, "%02x ", inpbuf[i]);
fprintf(stderr,"\n");
#endif
      pcap_rmap_xxxx(rmapc, inpbuf, inplen, outbuf, outlen);
#if 0      
fprintf(stderr,"outlen=%zu\n", outlen);
for(size_t i=0; i<outlen; i++) fprintf(stderr, "%02x ", outbuf[i]);
fprintf(stderr,"\n");
exit(1);
#endif
      ret = sp.write_packet(outbuf, outlen); // 0:success or ERROR_LOG_FATAL.
      if ( ret != 0 ) return ERROR_RUN;
    }
  }

  return 0;
}
 

int main(int argc, char *argv[])
{
  //// parse options

  pcapnc::init_class(argv[0]);
  
  int option_error = 0;
  while (1) {
    int option_index = 0;
    const int c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

    if ( c == -1 ) break;
    
    switch (c) {
    case 'a': param_after_wtime           = atof(optarg); if (param_after_wtime  < 0.0) param_after_wtime  = 0.0; break;
    case 'b': param_before_wtime          = atof(optarg); if (param_before_wtime < 0.0) param_before_wtime = 0.0; break;
    case 'c': param_config         = std::string(optarg); break;
    case 'n': param_channel        = std::string(optarg); break;
    case 'i': param_interval_sec          = atof(optarg); if (param_interval_sec < 0.0) param_interval_sec = 0.0; break;
    case 'o': param_original_time         =           1;  break;
    case 'r': param_reply_filename = std::string(optarg); break;
    case 't': param_store_filename = std::string(optarg); break;
    default:  option_error                =           1;  break;
    }
  }
  if (option_error) return ERROR_OPT;

  class rmap_channel rmapc;
  if ( param_channel != "" ){
    if ( param_config == "" ){
      pcapnc_logerr(PROGNAME "option '--channel' requires option '--config'\n"); 
      // @ test-pcap-replay-options1
      return ERROR_OPT;
    } 
    int ret = rmapc.read_json(param_config.c_str(), param_channel.c_str());
    if ( ret != 0 ){
      if        ( ret == rmap_channel::NOFILE ){
        pcapnc_logerr(PROGNAME "configuration file '%s' is not found\n", param_config.c_str());
        // @ test-pcap-replay-options3
      } else if ( ret == rmap_channel::JSON_ERROR ){
        pcapnc_logerr(PROGNAME "parse error in configuration file '%s'\n", param_config.c_str());
        // @ test-pcap-replay-options4
      } else {        // rmap_channel::NOCHANNEL
        pcapnc_logerr(PROGNAME "channel '%s' is not found\n", param_channel.c_str());
        // @ test-pcap-replay-options2
      }
      return ERROR_OPT;
    }
    use_rmap_channel = 1;
  }

  if ( param_reply_filename != ""  ){
    if ( ! use_rmap_channel ) {
      pcapnc_logerr(PROGNAME "option '--receive-reply' could be specified only for a RMAP channel.\n");
      // @ test-pcap-replay-options5
      return ERROR_OPT;      
    } else if ( ! rmapc.has_responces() ) {
      pcapnc_logerr(PROGNAME "option '--receive-reply' could not be specified for no-acknowledge-channel '%s'.\n",  param_channel.c_str());
      // @ test-pcap-replay-options6
      return ERROR_OPT;      
    }
    use_rmap_reply = 1;
  }

  if ( param_store_filename != ""  ){
    if ( ! use_rmap_channel ) {
      pcapnc_logerr(PROGNAME "option '--store-data' could be specified only for a RMAP Read channel.\n");
      // @ test-pcap-replay-options7
      return ERROR_OPT;      
    } else if ( rmapc.is_write_channel() ) {
      pcapnc_logerr(PROGNAME "option '--store-data' could not be specified for RMAP Write channel '%s'.\n",  param_channel.c_str());
      // @ test-pcap-replay-options8
      return ERROR_OPT;      
    } else if ( ! use_rmap_reply ) {
      // @ test-pcap-replay-options9
      pcapnc_logerr(PROGNAME "option '--store-data' requires option '--receive-reply'\n");
      return ERROR_OPT;      
    }
    store_rmap_read = 1;
  }

  ////

  pcapnc ip(1, "file");
  const int i_ret = ip.read_head(stdin); // 0:success, or ERROR LOG_FATAL.
  if ( i_ret != 0 ) return i_ret;

  pcapnc wp(!param_original_time, "output");
  const int w_ret = wp.write_nohead(stdout); // 0:success or ERROR_LOG_WARN.
  if ( w_ret != 0 ) return w_ret;

  pcapnc lp(1, "reply");
  if ( param_reply_filename != ""  ){
    // @ test-?????2?????-24-rmapr-rpl3
    const char *filename = param_reply_filename.c_str();
    const int r_ret = lp.read_nohead(filename); // 0:success, ERROR_PARAM, or ERROR_LOG_WARN.
    if ( r_ret != 0 ) {
      pcapnc_logerr(PROGNAME "file '%s' to receive reply could not be opend.\n",  filename);
      return ERROR_OPT;      
    }
  }

  pcapnc sp(!param_original_time, "store_data");
  if ( param_store_filename != ""  ){
    // @ test-?????2?????-24-rmapr-rpl3
    const char *filename = param_store_filename.c_str();
    const uint8_t linktype = 0x94; // Assume SpacePacket
    const int r_ret = sp.write_head(filename, linktype); // 0:success, ERROR_PARAM, ERROR_LOG_FATAL, or ERROR_LOG_WARN.
    if ( r_ret != 0 ) {
      pcapnc_logerr(PROGNAME "file '%s' to store data could not be opend.\n",  filename);
      return ERROR_OPT;      
    }
  }

  ////

  double prev_time = -1;
  
  while(1){
    static uint8_t input_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];
    uint8_t *const inpbuf = input_buf + PACKET_HEADER_SIZE;

    int ret;
    ret = ip.read_packet(inpbuf, PACKET_DATA_MAX_SIZE); // 0:success, -1:end of input, or ERROR_LOG_FATAL
    if ( ret <  0 ) { // end of input, withouog logging message
      // handle option '--after wait_sec' @ test-?????2?????-{14,15,23,24}*
      s3sim_sleep(param_after_wtime); 
      return 0; 
    }
    if ( ret >  0 ) return ERROR_RUN;

    //// time handling 

    double curr_time = ip._coarse_time + ip._nanosec * 1e-9;
    if ( prev_time < 0 ) {
      // handle option '--before wait_sec'
      // @ test-server2client*
      s3sim_sleep(param_before_wtime);
      prev_time = curr_time;
    } else {
      // handle option '--interval interval_sec'
      if        ( param_interval_sec == 0.0 ) {
        // zero is specified for interval_sec, do not sleep
      } else if ( param_interval_sec >  0.0 ) {
        // poisitive value is specified for interval_sec, constant iterval time
        // @ test-?????2?????*
      	s3sim_sleep(param_interval_sec); 
      } else {
        // inteval_sec is not specified, reproduce interval time of the input file
        const double tdiff = curr_time - prev_time;
	      s3sim_sleep(tdiff);
        prev_time = curr_time;
      }
    }

    // generated output
    size_t inplen = ip._caplen;
    if ( use_rmap_channel ) {
      if ( rmapc.is_write_channel() ){
        ret = pcap_rmapw_send(rmapc, wp, lp, inpbuf, inplen);
      } else {
        const uint8_t       *outbuf;
        size_t         outlen;
        ret = pcap_rmapr_recv_record(rmapc, wp, lp, sp, inpbuf, inplen, outbuf, outlen );
      }      
    } else {
      // @ test-?????2?????
      ret = pcap_ptp_send_record(wp, input_buf, inplen);
    }
    if ( ret != 0 ) return ERROR_RUN;

  }  
  return 0;
}
