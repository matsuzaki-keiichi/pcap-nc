#include <inttypes.h>
#include <stdlib.h>
// size_t

#define RMAP_MAX_NUM_PATH_ADDRESS 12

class rmap_channel {
    public:
    rmap_channel();

    void read_json(const char *file_name, const char *channel_name);

    int is_write_channel() const;
    int has_responces() const;

    void   generate_write_command(const uint8_t inbuf[],   size_t data_length, uint8_t trnsbuf[],        size_t *trnssize_p);
    void   generate_read_reply   (const uint8_t inbuf[],   size_t data_length, 
                                  const uint8_t recvbuf[], size_t recvsize,    uint8_t replybuf[],       size_t *replylen  ) const;

    size_t generate_read_command (                                             uint8_t trnsbuf[]);
    void   generate_write_reply  (const uint8_t recvbuf[], size_t recvsize,    uint8_t replybuf[],       size_t *replylen  ) const;

    void   validate_command      (const uint8_t recvbuf[], size_t recvsize,    const uint8_t **outbuf_p, size_t *outsize_p ) const;
    void   validate_reply        (const uint8_t recvbuf[], size_t recvsize,    const uint8_t **outbuf_p, size_t *outsize_p ) const;

    private:
    size_t generate_command_head (                                             uint8_t trnsbuf[]);
    void   generate_reply_head   (const uint8_t recvbuf[], size_t recvsize,    uint8_t replybuf[],       size_t *headlen   ) const;

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
