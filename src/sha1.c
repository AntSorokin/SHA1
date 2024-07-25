
#include "sha1.h"
/*
    Circular bit shift
    @param x value to shift
    @param n number of times to shift
    @return Circularly shifted value
*/
static uint32_t S(int n, uint32_t x) {
    return (x << n) | (x >> (32 - n)); 
}

/*
    The f function as defined in RFC 3174 section 5
*/
static uint32_t f(int t, uint32_t B, uint32_t C, uint32_t D) {
    if(0 <= t && t <= 19) {
        return ((B & C) | ((~B) & D));
    }
    else if((20 <= t && t <= 39) || (60 <= t && t <= 79)) {
        return (B ^ C ^ D);
    }
    else if(40 <= t && t <= 59) {
        return (B & C) | (B & D) | (C & D);
    }
}

/*
    The K function as defined in RFC 3174 section 5
*/
static uint32_t K(int t) {
    if(0 <= t && t <= 19) {
        return 0x5A827999;
    }
    else if(20 <= t && t <= 39) {
        return 0x6ED9EBA1;
    }
    else if(40 <= t && t <= 59) {
        return 0x8F1BBCDC;
    }
    else if(60 <= t  && t <= 79){
        return 0xCA62C1D6;
    }
}

/*
    Gets the padded value of the byte buffer at a certain byte_index as defined in RFC 3174 section 4.
    @param buf buffer to read from
    @param byte_size size of buf in bytes
    @param byte_index index to read the next four padded bytes from
    @param padded_len the total length of the buffer in bytes when padded
    @return Returns 4 bytes from the padded buffer in the range [byte_index, byte_index + 4)
*/
static uint32_t padded_val(const uint8_t* buf, uint64_t byte_size, uint64_t byte_index, uint64_t padded_len) {
    uint32_t val = 0;
    int shift = 24;

    //Reads bytes from the buffer if byte_index is with byte_size
    while(byte_index < byte_size && shift >= 0) {
        val |= (uint8_t)(*(buf + byte_index)) << shift;
        shift -= 8;
        byte_index++;
    }

    //Read the end bit after the buf
    if(byte_index == byte_size && shift >= 0) {
        val |= 0x80 << shift;
        shift -= 8;
        byte_index++;
    }
    
    //Adds the padding which is 0's
    while(byte_index < padded_len - 8 && shift >= 0) {
        shift -= 8;
        byte_index++;
    }

    //Adds the size of the buffer
    if(byte_index >= padded_len - 8) {
        union {
            uint64_t data;
            uint8_t bytes[8];
        } bit_size;
        bit_size.data = byte_size * 8;
        
        while(shift >= 0) {
            //Converts litte endian to big endian
            val |= bit_size.bytes[padded_len - byte_index - 1] << shift;
            shift -= 8;
            byte_index++;
        }
    }
    
    return val;
}


void sha1_message_digest(uint32_t H[5], const uint8_t* buf, uint64_t length) {
    H[0] = 0x67452301;
    H[1] = 0xEFCDAB89;
    H[2] = 0x98BADCFE;
    H[3] = 0x10325476;
    H[4] = 0xC3D2E1F0;
    
    //Computes the total length of the padded message in bytes
    const uint64_t padded_length = length + (64 - length % 64) + ((length % 64) >= 56) * 64;    
    uint32_t W[16];

    //Goes through each block of buf
    for(int i = 0; i < padded_length; i += 64) {
        //breaks block of 512 bits into 16 chunks
        for(int a = 0; a < 16; a++) {
            W[a] = padded_val(buf, length, i +  a * 4, padded_length);
        }

        uint32_t A = H[0];
        uint32_t B = H[1];
        uint32_t C = H[2];
        uint32_t D = H[3];
        uint32_t E = H[4];

        //Computes digest
        for(int t = 0; t <= 79; t++) {
            int s = t & 0xF;
            if (t >= 16) {
                W[s] = S(1, W[((s + 13) & 0xF)] ^ W[((s + 8) & 0xF)] ^ W[((s + 2) & 0xF)] ^ W[s]);
            } 

            const uint32_t TEMP = S(5, A) + f(t, B, C, D) + E + W[s] + K(t);
            E = D; 
            D = C; 
            C = S(30, B); 
            B = A; 
            A = TEMP;
        }  

        H[0] = H[0] + A;
        H[1] = H[1] + B;
        H[2] = H[2] + C;
        H[3] = H[3] + D;
        H[4] = H[4] + E;
    }

}


