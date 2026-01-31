#pragma once
#include <stdint.h>
#include <string.h>

/* Minimal MD5 + HMAC-MD5 implementation */

typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
} md5_ctx;

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) |
               ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);

    #define F(x,y,z) ((x&y)|(~x&z))
    #define G(x,y,z) ((x&z)|(y&~z))
    #define H(x,y,z) (x^y^z)
    #define I(x,y,z) (y^(x|~z))
    #define ROT(v,n) (((v)<<(n))|((v)>>(32-(n))))
    #define FF(a,b,c,d,x,s,ac) { a+=F(b,c,d)+x+ac; a=ROT(a,s)+b; }
    #define GG(a,b,c,d,x,s,ac) { a+=G(b,c,d)+x+ac; a=ROT(a,s)+b; }
    #define HH(a,b,c,d,x,s,ac) { a+=H(b,c,d)+x+ac; a=ROT(a,s)+b; }
    #define II(a,b,c,d,x,s,ac) { a+=I(b,c,d)+x+ac; a=ROT(a,s)+b; }

    FF(a,b,c,d,x[ 0], 7,0xd76aa478); FF(d,a,b,c,x[ 1],12,0xe8c7b756);
    FF(c,d,a,b,x[ 2],17,0x242070db); FF(b,c,d,a,x[ 3],22,0xc1bdceee);
    FF(a,b,c,d,x[ 4], 7,0xf57c0faf); FF(d,a,b,c,x[ 5],12,0x4787c62a);
    FF(c,d,a,b,x[ 6],17,0xa8304613); FF(b,c,d,a,x[ 7],22,0xfd469501);
    FF(a,b,c,d,x[ 8], 7,0x698098d8); FF(d,a,b,c,x[ 9],12,0x8b44f7af);
    FF(c,d,a,b,x[10],17,0xffff5bb1); FF(b,c,d,a,x[11],22,0x895cd7be);
    FF(a,b,c,d,x[12], 7,0x6b901122); FF(d,a,b,c,x[13],12,0xfd987193);
    FF(c,d,a,b,x[14],17,0xa679438e); FF(b,c,d,a,x[15],22,0x49b40821);

    GG(a,b,c,d,x[ 1], 5,0xf61e2562); GG(d,a,b,c,x[ 6], 9,0xc040b340);
    GG(c,d,a,b,x[11],14,0x265e5a51); GG(b,c,d,a,x[ 0],20,0xe9b6c7aa);
    GG(a,b,c,d,x[ 5], 5,0xd62f105d); GG(d,a,b,c,x[10], 9,0x02441453);
    GG(c,d,a,b,x[15],14,0xd8a1e681); GG(b,c,d,a,x[ 4],20,0xe7d3fbc8);
    GG(a,b,c,d,x[ 9], 5,0x21e1cde6); GG(d,a,b,c,x[14], 9,0xc33707d6);
    GG(c,d,a,b,x[ 3],14,0xf4d50d87); GG(b,c,d,a,x[ 8],20,0x455a14ed);
    GG(a,b,c,d,x[13], 5,0xa9e3e905); GG(d,a,b,c,x[ 2], 9,0xfcefa3f8);
    GG(c,d,a,b,x[ 7],14,0x676f02d9); GG(b,c,d,a,x[12],20,0x8d2a4c8a);

    HH(a,b,c,d,x[ 5], 4,0xfffa3942); HH(d,a,b,c,x[ 8],11,0x8771f681);
    HH(c,d,a,b,x[11],16,0x6d9d6122); HH(b,c,d,a,x[14],23,0xfde5380c);
    HH(a,b,c,d,x[ 1], 4,0xa4beea44); HH(d,a,b,c,x[ 4],11,0x4bdecfa9);
    HH(c,d,a,b,x[ 7],16,0xf6bb4b60); HH(b,c,d,a,x[10],23,0xbebfbc70);
    HH(a,b,c,d,x[13], 4,0x289b7ec6); HH(d,a,b,c,x[ 0],11,0xeaa127fa);
    HH(c,d,a,b,x[ 3],16,0xd4ef3085); HH(b,c,d,a,x[ 6],23,0x04881d05);
    HH(a,b,c,d,x[ 9], 4,0xd9d4d039); HH(d,a,b,c,x[12],11,0xe6db99e5);
    HH(c,d,a,b,x[15],16,0x1fa27cf8); HH(b,c,d,a,x[ 2],23,0xc4ac5665);

    II(a,b,c,d,x[ 0], 6,0xf4292244); II(d,a,b,c,x[ 7],10,0x432aff97);
    II(c,d,a,b,x[14],15,0xab9423a7); II(b,c,d,a,x[ 5],21,0xfc93a039);
    II(a,b,c,d,x[12], 6,0x655b59c3); II(d,a,b,c,x[ 3],10,0x8f0ccc92);
    II(c,d,a,b,x[10],15,0xffeff47d); II(b,c,d,a,x[ 1],21,0x85845dd1);
    II(a,b,c,d,x[ 8], 6,0x6fa87e4f); II(d,a,b,c,x[15],10,0xfe2ce6e0);
    II(c,d,a,b,x[ 6],15,0xa3014314); II(b,c,d,a,x[13],21,0x4e0811a1);
    II(a,b,c,d,x[ 4], 6,0xf7537e82); II(d,a,b,c,x[11],10,0xbd3af235);
    II(c,d,a,b,x[ 2],15,0x2ad7d2bb); II(b,c,d,a,x[ 9],21,0xeb86d391);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;

    #undef F
    #undef G
    #undef H
    #undef I
    #undef ROT
    #undef FF
    #undef GG
    #undef HH
    #undef II
}

static void md5_init(md5_ctx *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(md5_ctx *ctx, const uint8_t *data, size_t len) {
    size_t idx = ctx->count % 64;
    ctx->count += len;
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == 64) {
            md5_transform(ctx->state, ctx->buffer);
            idx = 0;
        }
    }
}

static void md5_final(uint8_t digest[16], md5_ctx *ctx) {
    uint8_t pad[64] = {0x80};
    uint64_t bits = ctx->count * 8;
    size_t idx = ctx->count % 64;
    size_t padlen = (idx < 56) ? (56 - idx) : (120 - idx);
    md5_update(ctx, pad, padlen);
    uint8_t bitbuf[8];
    for (int i = 0; i < 8; i++) bitbuf[i] = (bits >> (i*8)) & 0xff;
    md5_update(ctx, bitbuf, 8);
    for (int i = 0; i < 4; i++) {
        digest[i*4+0] = (ctx->state[i]) & 0xff;
        digest[i*4+1] = (ctx->state[i] >> 8) & 0xff;
        digest[i*4+2] = (ctx->state[i] >> 16) & 0xff;
        digest[i*4+3] = (ctx->state[i] >> 24) & 0xff;
    }
}

/* HMAC-MD5: RFC 2104 */
static void hmac_md5(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t digest[16]) {
    uint8_t k[64] = {0};
    md5_ctx ctx;

    if (key_len > 64) {
        md5_init(&ctx);
        md5_update(&ctx, key, key_len);
        md5_final(k, &ctx);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner: H(ipad || data) */
    md5_init(&ctx);
    md5_update(&ctx, ipad, 64);
    md5_update(&ctx, data, data_len);
    uint8_t inner[16];
    md5_final(inner, &ctx);

    /* outer: H(opad || inner) */
    md5_init(&ctx);
    md5_update(&ctx, opad, 64);
    md5_update(&ctx, inner, 16);
    md5_final(digest, &ctx);
}

/* Compute HMAC-MD5 and write as uppercase ASCII hex */
static void hmac_md5_hex(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         char *hex_out /* must be >= 33 bytes */) {
    uint8_t digest[16];
    hmac_md5(key, key_len, data, data_len, digest);
    const char *hexchars = "0123456789ABCDEF";
    for (int i = 0; i < 16; i++) {
        hex_out[i*2]   = hexchars[(digest[i] >> 4) & 0xf];
        hex_out[i*2+1] = hexchars[digest[i] & 0xf];
    }
    hex_out[32] = '\0';
}
