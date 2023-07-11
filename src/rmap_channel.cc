#include "rmap_channel.h"

#include <fstream>
#include <iostream>
#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"
// using namespace rapidjson;

#include <boost/algorithm/string.hpp>
#include <string>
#include <list>
#include <boost/foreach.hpp>
using namespace std;

#include <stdio.h>
#include <string.h>
// memcpy

#define ERROR_LOG_FATAL 13

#define pcapnc_logerr(...) fprintf(stderr, __VA_ARGS__) // TODO ...hhh...

static long long parse_hex_longlong(const char *s, const char *varname, const char *channel_name){
    if ( s[0] != '0' || s[1] != 'x' ) {
        pcapnc_logerr("%s of the channel '%s' shall start with '0x'.\n", varname, channel_name);
        exit(1);        
    }

    char *endptr;
    const long long llvalue = strtoull(s+2, &endptr, 16);
    if ( *endptr != 0 ) {
        pcapnc_logerr("%s(%s) of the channel '%s' shall be a number.\n", varname, s, channel_name);
        exit(1);        
    }
    return llvalue;
}

static uint8_t read_hex_uint8(const rapidjson::Value &obj, const char *varname, const char *channel_name){
    const char* s = obj[varname].GetString();
    const long long llvalue = parse_hex_longlong(s, varname, channel_name);
    if ( llvalue >= 0x100 || llvalue < 0 ) {
        pcapnc_logerr("%s(%s) of the channel '%s' shall be 1 byte value.\n", varname, s, channel_name);
        exit(1);        
    }
    return (uint8_t) llvalue;    
}

static uint32_t read_hex_uint24(const rapidjson::Value &obj, const char *varname, const char *channel_name){
    const char* s = obj[varname].GetString();
    const long long llvalue = parse_hex_longlong(s, varname, channel_name);
    if ( llvalue >= 0x1000000 || llvalue < 0 ) {
        pcapnc_logerr("%s of the channel '%s' shall be 3 byte value.\n", varname, channel_name);
        exit(1);        
    }
    return (uint32_t) llvalue;    
}

static uint64_t read_hex_uint40(const rapidjson::Value &obj, const char *varname, const char *channel_name){
    const char* s = obj[varname].GetString();
    const long long llvalue = parse_hex_longlong(s, varname, channel_name);
    if ( llvalue >= 0x10000000000 || llvalue < 0 ) {
        pcapnc_logerr("%s of the channel '%s' shall be 5 byte value.\n", varname, channel_name);
        exit(1);        
    }
    return (uint64_t) llvalue;    
}

static int read_hex_chars(const rapidjson::Value &obj, const char *varname, uint8_t out_buffer[], int buffer_size, const char *channel_name){
    const char* t = obj[varname].GetString();
    string str(t);

    list<string> list_string;
 
    boost::split(list_string, str, boost::is_space());

    int i=0;
    BOOST_FOREACH(string s, list_string) {
        if ( i>=buffer_size ) {
            pcapnc_logerr("Size of %s of the channel '%s' exceeds %d.\n", varname, channel_name, buffer_size);
            exit(1);        
        }
        const long long llvalue = parse_hex_longlong(s.c_str(), varname, channel_name);
        if ( llvalue >= 32 || llvalue < 0 ) {
            pcapnc_logerr("%s(%s) of the channel '%s' shall be in the range from 0 to 31.\n", varname, s.c_str(), channel_name);
            exit(1);        
        }
        out_buffer[i] = (uint8_t) llvalue;
        i++;
    }
    return i;
}

rmap_channel::rmap_channel(){

    num_dpa_padding = 0;   
    num_dpa         = 4;
    d_path_address[0] = 0x04;
    d_path_address[1] = 0x03;
    d_path_address[2] = 0x02;
    d_path_address[3] = 0x01;
    destination_logical_address = 0x90;
    destination_key             = 0x6f;

    num_spa_padding = 0;   
    num_spa         = 4;
    s_path_address[0] = 0x01; 
    s_path_address[1] = 0x02; 
    s_path_address[2] = 0x03; 
    s_path_address[3] = 0x04; 
    source_logical_address      = 0x91;

    memory_address              = 0x6789abcdef;

    transaction_id              = 0x9999;
}

/**
  @return 0:success, othewise fail. 1:File Does Not Exist
*/

int rmap_channel::read_json(const char *file_name, const char *channel_name)
{
    std::ifstream ifs(file_name);
    if ( !ifs.is_open() )
    {
        return rmap_channel::NOFILE;
    }

    rapidjson::IStreamWrapper isw(ifs);

    rapidjson::Document doc;
    doc.ParseStream(isw);
    if ( doc.HasParseError() ){
        return rmap_channel::JSON_ERROR;
    }

    int status = rmap_channel::NOCHANNEL;

    const rapidjson::Value& channels = doc[ "channels" ];

    for (rapidjson::Value::ConstValueIterator itr = channels.Begin(); itr != channels.End(); ++itr) {
        const rapidjson::Value& channel = *itr;

        string name = channel["name"].GetString();
        if ( name != channel_name ) continue;

        this->num_dpa = read_hex_chars(channel, "destination_path_address", this->d_path_address, RMAP_MAX_NUM_PATH_ADDRESS, channel_name);
        this->num_spa = read_hex_chars(channel, "source_path_address",      this->s_path_address, RMAP_MAX_NUM_PATH_ADDRESS, channel_name);

        this->num_dpa_padding = (RMAP_MAX_NUM_PATH_ADDRESS - this->num_dpa) % 4;
        this->num_spa_padding = (RMAP_MAX_NUM_PATH_ADDRESS - this->num_spa) % 4;

        this->destination_logical_address = read_hex_uint8 (channel, "destination_logical_address", channel_name);
        this->destination_key             = read_hex_uint8 (channel, "destination_key"            , channel_name);
        this->source_logical_address      = read_hex_uint8 (channel, "source_logical_address"     , channel_name);
        this->instruction                 = read_hex_uint8 (channel, "instruction"                , channel_name);
        this->memory_address              = read_hex_uint40(channel, "memory_address"             , channel_name);

        if ( this->instruction & 0x03 ) {
            pcapnc_logerr("Lower 2bits of the istruction (%02x) of the channel '%s' shall be 0.\n", this->instruction, channel_name);
            exit(1);        
        }

        if ( channel.HasMember("data_length") ) {
            this->data_length             = read_hex_uint24(channel, "data_length"                , channel_name);
        } else {
            this->data_length = 0;
        }

        status = 0;

#ifdef DEBUG
        std::cout << "destination_path_address:    " << channel["destination_path_address"]    .GetString() << std::endl;
        std::cout << "destination_logical_address: " << channel["destination_logical_address"] .GetString() << std::endl;
        std::cout << "destination_key:             " << channel["destination_key"]             .GetString() << std::endl;
        std::cout << "source_path_address:         " << channel["source_path_address"]         .GetString() << std::endl;
        std::cout << "source_logical_address:      " << channel["source_logical_address"]      .GetString() << std::endl;
        std::cout << "memory_address:              " << channel["memory_address"]              .GetString() << std::endl;
#endif    
    }

    return status;
}

/**
  @param hedbuf [out] 
   Note: size shall be >=40(=16+12+12)
  @param hedlen [in,out]
   Note: 16..40
   Note: Enough buffer size shall be provided becase no check is performed.
 */

void rmap_channel::generate_command_head(uint8_t hedbuf[], size_t &hedlen) {
    // This function generate a part of Command Header also for RMAP Write command

    const int m = this->num_dpa;
    const int n = this->num_spa + this->num_spa_padding;

    const int source_path_address_length = n >> 2; 
    const uint8_t field2 = (this->instruction & 0xFC) | (source_path_address_length & 0x03);

    // Wrire Command (e.g. 0x60, without verify, without acknowledge, without increment)
    // Instruction field = RMAP Command + Source Path Address Length
    //  0b: reserved
    //  1b: command
    //  1b: write
    //  ?b: no verify / verify
    //  ?b: without acknowledge / with acknowledge
    //  ?b: no increment / increment
    // xxb: source path address length

    memcpy(hedbuf, this->d_path_address, this->num_dpa);

    uint8_t *const cargo = hedbuf + m;

    cargo[ 0] = this->destination_logical_address;
    cargo[ 1] = RMAP_PROTOCOL_ID;
    cargo[ 2] = field2;
    cargo[ 3] = this->destination_key;

    // source path address
    memset(cargo+4, 0, this->num_spa_padding);
    memcpy(cargo+4+this->num_spa_padding, this->s_path_address, this->num_spa);

    cargo[ 4+n] =  this->source_logical_address;
    cargo[ 5+n] = (this->transaction_id >>  8) & 0xFF;
    cargo[ 6+n] = (this->transaction_id >>  0) & 0xFF;
    cargo[ 7+n] = (this->memory_address >> 32) & 0xFF;
    cargo[ 8+n] = (this->memory_address >> 24) & 0xFF;
    cargo[ 9+n] = (this->memory_address >> 16) & 0xFF;
    cargo[10+n] = (this->memory_address >>  8) & 0xFF;
    cargo[11+n] = (this->memory_address >>  0) & 0xFF;
    cargo[12+n] = (this->data_length    >> 16) & 0xFF;
    cargo[13+n] = (this->data_length    >>  8) & 0xFF;
    cargo[14+n] = (this->data_length    >>  0) & 0xFF;
    cargo[15+n] = rmap_channel::rmap_calculate_crc(cargo, 15+n); /* Header CRC */

    this->transaction_id = this->transaction_id + 1;

    hedlen = 16+m+n;
}

/**
  @param cmdbuf [out]
   Note: size shall be >=40(=16+12+12)
  @param cmdlen [in,out]
   Note: 16..40
   Note: Enough buffer size shall be provided becase no check is performed.
 */

void rmap_channel::generate_read_command(uint8_t cmdbuf[], size_t &cmdlen) {
    this->generate_command_head(cmdbuf, cmdlen);
}

/**
  @param inpbuf [in]
  @param inplen [in]
  @param cmdbuf [out]
   Note: size shall be >=40(=16+12+12)+inplen
  @param cmdlen [in,out]
   Note: [16..40]+inplen
  @return 0:success or ERROR_LOG_FATAL (i.e. result of buffer size check).
 */

int rmap_channel::generate_write_command(const uint8_t inpbuf[], size_t inplen, uint8_t cmdbuf[], size_t &cmdlen) {

    // this method should be called only for RMAP Write Command 
    // i.e. this->instruction & 0x20 != 0

    this->data_length = inplen;

    size_t hedlen;
    this->generate_command_head(cmdbuf, hedlen);

    const size_t cmdlen1 = hedlen + inplen + 1 /* CRC length */;
    if ( cmdlen1 > cmdlen ) {
        pcapnc_logerr("output size (%zu) exceeds the buffer size (%zu).\n", cmdlen1, cmdlen);
        return ERROR_LOG_FATAL;
    }
    cmdlen = cmdlen1;    

    uint8_t *const data = cmdbuf + hedlen;
    memcpy(data, inpbuf, inplen);
    data[inplen] = rmap_channel::rmap_calculate_crc(data, inplen); /* Data CRC */

    return 0;
}

/**
  @param rcvbuf [in]
  @param rcvlen [in]
  @param hedbuf [out]
   Note: size shall be >=20(=8+12)
  @param hedlen [in,out]
   Note: 8..20
   Note: Enough buffer size shall be provided becase no check is performed.
 */

void rmap_channel::generate_reply_head(const uint8_t rcvbuf[], size_t rcvlen, uint8_t hedbuf[], size_t &hedlen) const {
    const uint8_t command_instruction = rcvbuf[2];
    const int source_path_address_length = command_instruction & 0x03;
    const size_t n = source_path_address_length << 2;
    const uint8_t status = 0; // TODO implement status ??

    size_t m=0;
    for ( size_t i=0; i<n ; i++ ){
        uint8_t ad = rcvbuf[4+i];
        if ( ad == 0 && i != n-1 ) continue;
        hedbuf[m++] = ad;
    }

    const uint8_t reply_instruction = command_instruction & (0xFF - 0x43);
    
    uint8_t *const cargo = hedbuf + m;
    cargo[0] = this->source_logical_address;
    cargo[1] = RMAP_PROTOCOL_ID;
    cargo[2] = reply_instruction;
    cargo[3] = status;
    cargo[4] = this->destination_logical_address;
    cargo[5] = rcvbuf[ 5+n];
    cargo[6] = rcvbuf[ 6+n];
    hedlen = m+8;
}

/**
  @param rcvbuf [in]
  @param rcvlen [in]
  @param rplbuf [out]
   Note: size shall be >=20(=8+12)
  @param rpllen [in,out]
   Note: 8..20
   Note: Enough buffer size shall be provided becase no check is performed.
 */

void rmap_channel::generate_write_reply(const uint8_t rcvbuf[], size_t rcvlen, uint8_t rplbuf[], size_t &rpllen) const {
    size_t hedlen = rpllen;
    this -> generate_reply_head(rcvbuf, rcvlen, rplbuf, hedlen);

    uint8_t *const cargo = rplbuf + hedlen - 8;
    cargo[7] = rmap_channel::rmap_calculate_crc(cargo, 7); /* Header CRC */

    rpllen = hedlen;
}

/**
  @param inpbuf [in]
  @param inplen [in]
  @param rcvbuf [in]
  @param rcvlen [in]
  @param rplbuf [out]
   Note: size shall be >=20(=8+12)+inplen
  @param rpllen [in,out]
   Note: [8..20]+inplen
  @return 0:success or ERROR_LOG_FATAL (i.e. result of buffer size check).
*/

int rmap_channel::generate_read_reply(const uint8_t inpbuf[], size_t inplen, const uint8_t rcvbuf[], size_t rcvlen, uint8_t rplbuf[], size_t &rpllen) const {
    size_t hedlen = rpllen;

    this -> generate_reply_head(rcvbuf, rcvlen, rplbuf, hedlen);

    uint8_t *const cargo = rplbuf + hedlen - 8;
    cargo[ 7] = 0x00;
    cargo[ 8] = (inplen >> 16) & 0xFF;
    cargo[ 9] = (inplen >>  8) & 0xFF;
    cargo[10] = (inplen >>  0) & 0xFF;
    cargo[11] = rmap_channel::rmap_calculate_crc(cargo, 11); /* Header CRC */

    const size_t rpllen1 = hedlen + 4 + inplen + 1 /* Data CRC */;
    if ( rpllen1 > rpllen ) {
        pcapnc_logerr("Size of RMAP Reply (%zu) exceeds the buffer size (%zu).\n", rpllen1, rpllen);
        return ERROR_LOG_FATAL;
    }

    uint8_t *const data = cargo + 12;
    memcpy(data, inpbuf, inplen);
    data[inplen] = rmap_channel::rmap_calculate_crc(data, inplen); /* Data CRC */

    rpllen = rpllen1;

    return 0;
}

/**
  @param rcvbuf [in]
  @param rcvlen [in]
  @param outbuf [out] rcvbuf..rcvbuf+recvlen or NULL
   Note: NULL for a read channel.
  @param outlen [in,out] 0..rcvlen
   Note: 0 for a read channel.
 */

void rmap_channel::validate_command(const uint8_t rcvbuf[], size_t rcvlen, const uint8_t *&outbuf, size_t &outlen) const {
    const uint8_t *const cargo = rcvbuf;

    if ( !this->is_write_channel() && rcvlen != 16 ){
        pcapnc_logerr("Length of a Read Command is not 16 but 0x%zu.\n", rcvlen);
        return;       
    }

    if ( cargo[0] != this->destination_logical_address ){
        pcapnc_logerr("Destination Logical Address is not 0x%02x but 0x%02x.\n", 
            this->destination_logical_address, cargo[0]);
        return;       
    }

    if ( cargo[1] != RMAP_PROTOCOL_ID ){
        pcapnc_logerr("Protocol ID is not 0x%02x but 0x%02x.\n", 
            RMAP_PROTOCOL_ID, cargo[1]);
        return;       
    }

    const uint8_t instruction            = cargo[2] & 0xFC;
    const int source_path_address_length = cargo[2] & 0x03; 
    const int n = source_path_address_length << 2;

    const uint8_t header_crc = rmap_channel::rmap_calculate_crc(cargo, 15+n);
    if ( cargo[15+n] != header_crc ){
        pcapnc_logerr("Header CRC Error.\n");
        return;       
    }

    if ( instruction != this->instruction ) {
        pcapnc_logerr("Instruction is not 0x%02x but 0x%02x.\n", 
            this->instruction, instruction & 0xFC);
        return;       
    }

    if ( cargo[3] != this->destination_key ){
        pcapnc_logerr("Protocol ID is not 0x%02x but 0x%02x.\n", 
            this->destination_key, cargo[3]);
        return;       
    }

    const uint64_t address = (((uint64_t) cargo[ 7+n]) << 32)
        +                    (((uint64_t) cargo[ 8+n]) << 24)
        +                    (((uint64_t) cargo[ 9+n]) << 16)
        +                    (((uint64_t) cargo[10+n]) <<  8) 
        +                    (((uint64_t) cargo[11+n]) <<  0);

    if ( address != this->memory_address ){
        pcapnc_logerr("Write Address is not 0x%10" PRIx64 " but 0x%10" PRIx64 ".\n", 
            this->memory_address, address);
        return;       
    }

    if ( cargo[4+n] != this->source_logical_address ){
        pcapnc_logerr("Source Logical Address is not 0x%02x but 0x%02x.\n", 
            this->source_logical_address, cargo[4+n]);
        return;       
    }
#if 0
    const uint16_t transaction_id =        (cargo[ 5+n]  <<  8) 
        +                                  (cargo[ 6+n]  <<  0);
#endif
    const size_t   outlen1 = (((size_t) cargo[12+n]) << 16)
        +                    (((size_t) cargo[13+n]) <<  8) 
        +                    (((size_t) cargo[14+n]) <<  0);

    if ( !this->is_write_channel() ) {
        outbuf = NULL;
        outlen = 0;
    } else {
        if ( 16+n+outlen1+1 != rcvlen ){
            pcapnc_logerr("Data Length (%zu) is not consistent received packet size (%zu).\n", 
                outlen1, rcvlen);
            return;       
        }
        const uint8_t *const data = cargo + 16 + n;
        const uint8_t data_crc = rmap_channel::rmap_calculate_crc(data, outlen1);
        if ( data[outlen1] != data_crc ){
            pcapnc_logerr("Data CRC Error.\n");
            return;
        }       
        outbuf = data;
        outlen = outlen1;
    }
}

/**
  @param rcvbuf [in]
  @param rcvlen [in]
  @param outbuf [out]
   Note: NULL for a write channel.
  @param outlen [in,out]
   Note: 0 for a write channel.
 */

void rmap_channel::validate_reply(const uint8_t rcvbuf[], size_t rcvlen, const uint8_t *&outbuf, size_t &outlen) const {

    // Wrire Reply (e.g. 0x28)
    // Instruction field = RMAP Reply
    //  0b: reserved
    //  0b: response
    //  1b: write
    //  ?b: no verify (?)
    //  1b: with acknowledge
    //  ?b: no increment (?)
    // 00b: source path address length

    const uint8_t *const cargo = rcvbuf;

    if ( this->is_write_channel() && rcvlen != 8 ){
        pcapnc_logerr("Length of a Write Reply is not 8 but 0x%zu.\n", rcvlen);
        return;       
    }
    if ( cargo[0] != this->source_logical_address ){
        pcapnc_logerr("Destination Logical Address is not 0x%02x but 0x%02x.\n", 
            this->source_logical_address, cargo[0]);
        return;       
    }

    if ( cargo[1] != RMAP_PROTOCOL_ID ){
        pcapnc_logerr("Protocol ID is not 0x%02x but 0x%02x.\n", 
            RMAP_PROTOCOL_ID, cargo[1]);
        return;       
    }

    const uint8_t expected_instruction = this->instruction & (0xFF - 0x43);
    if ( cargo[2] != expected_instruction ) {
        pcapnc_logerr("Instruction is not 0x%02x but 0x%02x.\n", 
            expected_instruction, cargo[2]);
        return;       
    }

    // cargo[3] = status;

    if ( cargo[4] != this->destination_logical_address ){
        pcapnc_logerr("Source Logical Address is not 0x%02x but 0x%02x.\n", 
            this->destination_logical_address, cargo[4]);
        return;       
    }

    uint16_t transaction_id =  (cargo[5] << 8) + cargo[6];
    uint16_t expected_transaction_id = (uint16_t)(this->transaction_id-1); 
    if ( transaction_id != expected_transaction_id ){
        pcapnc_logerr("Transaction ID is not 0x%02" PRIx16 " but 0x%02" PRIx16 ".\n", 
            expected_transaction_id, transaction_id);
        return;       
    }

    if ( this->is_write_channel() ) {
        const uint8_t crc = rmap_channel::rmap_calculate_crc(cargo, 7);
        if ( cargo[7] != crc ){
            pcapnc_logerr("Header CRC Error.\n");
            return;       
        }
        outbuf = NULL;
        outlen = 0;
    } else {
        const uint8_t header_crc = rmap_channel::rmap_calculate_crc(cargo, 11);
        const size_t outlen1 = (((size_t) cargo[ 8]) << 16)
                             + (((size_t) cargo[ 9]) <<  8)
                             + (((size_t) cargo[10]) <<  0);
        if ( cargo[11] != header_crc ) {
            pcapnc_logerr("Header CRC Error.\n");
            return;       
        }

        const uint8_t *const data = cargo + 12;
        const uint8_t data_crc = rmap_channel::rmap_calculate_crc(data, outlen1); /* Data CRC */
        if ( data[outlen1] != data_crc ) {
            pcapnc_logerr("Data CRC Error.\n");
        }

        outbuf = data;
        outlen = outlen1;
    }
    return;
}

/**
  @param inpbuf [in]
  @param inplen [in]
  @param outbuf [out] inpbuf..inpbuf+inplen
  @param outlen [out] 0..inplen
 */

void rmap_channel::remove_path_address(const uint8_t inpbuf[], size_t inplen,   const uint8_t *&outbuf,   size_t &outlen) {
    const size_t num_path_address = rmap_channel::rmap_num_path_address(inpbuf, inplen);
    outbuf = inpbuf + num_path_address; 
    outlen = inplen - num_path_address;
}

// #define DEBUG

// Reference: https://gist.github.com/yuasatakayuki/e2acc1b1a40307257c14dcd4040ec1c4

static const uint8_t RMAP_CRC_TABLE[] = {
    0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75,  // 0
    0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,  // 1
    0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69,  // 2
    0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,  // 3
    0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d,  // 4
    0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,  // 5
    0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51,  // 6
    0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,  // 7
    0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05,  // 8
    0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,  // 9
    0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19,  // 10
    0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,  // 11
    0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d,  // 12
    0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,  // 13
    0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21,  // 14
    0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,  // 15

    0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95,  // 16
    0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,  // 17
    0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89,  // 18
    0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,  // 19
    0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad,  // 20
    0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,  // 21
    0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1,  // 22
    0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,  // 23
    0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5,  // 24
    0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,  // 25
    0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9,  // 26
    0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,  // 27
    0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd,  // 28
    0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,  // 29
    0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1,  // 30
    0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf   // 31
};

uint8_t rmap_channel::rmap_calculate_crc(const uint8_t data[], size_t length) {
    uint8_t crc = 0x00;
    for (size_t i = 0; i < length; i++) {
        crc = RMAP_CRC_TABLE[(crc ^ data[i]) & 0xff];
    }
    return crc;
}

size_t rmap_channel::rmap_num_path_address(const uint8_t inbuf[], size_t insize){
    size_t i;
    for ( i=0; i<insize; i++ ){
        if ( inbuf[i] >= 32 ) break;      
    }
    return i;
}
