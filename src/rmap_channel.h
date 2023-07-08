#include <inttypes.h>
#include <stdlib.h>
// size_t

#define RMAP_MAX_NUM_PATH_ADDRESS 12

#define RMAP_INST_WRITE  0x20
#define RMAP_INST_REPLY  0x08

class rmap_channel {
  public:
    rmap_channel();

    enum {NOFILE=1, JSON_ERROR=2, NOCHANNEL=3};

    int read_json(const char *file_name, const char *channel_name);

    inline int is_read_channel()  const { return ! this->is_write_channel(); }
    inline int is_write_channel() const { return this->instruction & RMAP_INST_WRITE; }
    inline int has_responces()    const { return this->instruction & RMAP_INST_REPLY; }

//                                 INPUT                                            OUTPUT
  private:
    void generate_command_head  (                                               uint8_t   hedbuf[], size_t &hedlen);
  public:
    void generate_write_command (const uint8_t inpbuf[], size_t inplen,         uint8_t   cmdbuf[], size_t &cmdlen);
    void generate_read_command  (                                               uint8_t   cmdbuf[], size_t &cmdlen);
  private:    
    void generate_reply_head    (const uint8_t rcvbuf[], size_t rcvlen,         uint8_t   hedbuf[], size_t &hedlen) const;
  public:
    void generate_write_reply   (const uint8_t rcvbuf[], size_t rcvlen,         uint8_t   rplbuf[], size_t &rpllen) const;
    void generate_read_reply    (const uint8_t inpbuf[], size_t inplen,   
                                   const uint8_t rcvbuf[], size_t rcvlen,         uint8_t   rplbuf[], size_t &rpllen) const;  
    void validate_command       (const uint8_t rcvbuf[], size_t rcvlen,   const uint8_t *&outbuf,   size_t &outlen) const;
    void validate_reply         (const uint8_t rcvbuf[], size_t rcvlen,   const uint8_t *&outbuf,   size_t &outlen) const;

  public:
    uint8_t  d_path_address[RMAP_MAX_NUM_PATH_ADDRESS]; size_t num_dpa;
    uint8_t  s_path_address[RMAP_MAX_NUM_PATH_ADDRESS]; size_t num_spa;
    size_t   num_dpa_padding;   
    size_t   num_spa_padding;   
    uint8_t  destination_logical_address;
    uint8_t  destination_key;
    uint8_t  source_logical_address;
    uint8_t  instruction;
    uint64_t memory_address;
    size_t   data_length;

    uint16_t transaction_id;
};

extern "C" {

extern void rmap_read_json();
extern uint8_t rmap_calculate_crc(const uint8_t data[], size_t length);
extern size_t rmap_num_path_address(const uint8_t inbuf[], size_t insize);

}
