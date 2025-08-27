#ifndef _ENC_MESSAGE
#define _ENC_MESSAGE

#include "common.h"

/*
 * structure of the message to be sent over
 * the secure channel after DH key exchange
 *
 * */
struct header {
    /* 
     * bit 7-6-5-4-3:
     *  - specification code for why the request failed
     *  - all bits zero if it's successful
     *
     * bit 2:
     *  - 0: the reponse is successful
     *  - 1: the reponse failed
     *
     * bits 1-0:
     *  - type of request made to the server
     *  - this field is unrelevant for the respective response
     *  - 00: create keys
     *  - 01: signDoc
     *  - 10: getPublicKey
     *  - 11: deleteKeys */
    uint8_t type;
    /* length of the message to be sent */
    uint64_t length;
    
    inline void successful(uint8_t code) { type |= (code << 3); type &= ~(0x04); } // set the code and reset the bit 1
    
    inline void failed(uint8_t code) { type |= (code << 3); type |= (0x02); }
    
    /* serialize the struct into a byte_vec */
    inline byte_vec serialize() const {
        byte_vec out(1 + 8);
        out[0] = type;
        // big-endian encode of length
        uint64_t L = length;
        out[1] = static_cast<uint8_t>((L >> 56) & 0xFF);
        out[2] = static_cast<uint8_t>((L >> 48) & 0xFF);
        out[3] = static_cast<uint8_t>((L >> 40) & 0xFF);
        out[4] = static_cast<uint8_t>((L >> 32) & 0xFF);
        out[5] = static_cast<uint8_t>((L >> 24) & 0xFF);
        out[6] = static_cast<uint8_t>((L >> 16) & 0xFF);
        out[7] = static_cast<uint8_t>((L >>  8) & 0xFF);
        out[8] = static_cast<uint8_t>( L        & 0xFF);
        return out;
    }

    /* deserialize struct from a byte_vec */
    static inline bool deserialize(const uint8_t* buf, size_t len, header& out) {
        if (len < 9) return false;
        out.type = buf[0];
        out.length =
            (static_cast<uint64_t>(buf[1]) << 56) |
            (static_cast<uint64_t>(buf[2]) << 48) |
            (static_cast<uint64_t>(buf[3]) << 40) |
            (static_cast<uint64_t>(buf[4]) << 32) |
            (static_cast<uint64_t>(buf[5]) << 24) |
            (static_cast<uint64_t>(buf[6]) << 16) |
            (static_cast<uint64_t>(buf[7]) <<  8) |
            (static_cast<uint64_t>(buf[8])      );
        return true;
    }

    /* deserialize from byte_vec */
    static inline bool deserialize(const byte_vec& in, header& out) {
        return deserialize(in.data(), in.size(), out);
    }
};

#endif
