#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "crypto/ecdsa.h"
#include "crypto/sha2.h"
#include "crypto/secp256k1.h"

/* 
  Trezor’s ecdsa.h (from GitHub master) declares:
    int point_multiply(const ecdsa_curve *curve,
                       const bignum256 *k,
                       const curve_point *p,
                       curve_point *res);
  We use it for both ephemeral key generation and ECDH.
*/

typedef bignum256 BigInt;  //a 32 byte integer(since in c we have support only for 32/64 bits)

/* ---------- Hex Conversion Helpers ----------- */
static int hexchar_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) return 0; //should be exactly 64
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexchar_to_int(hex[2 * i]);
        int lo = hexchar_to_int(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (hi << 4) | lo;
    }
    return 1;
}

static void bytes_to_hex(const uint8_t *in, size_t in_len, char *out) {
    static const char *hex_chars = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[2 * i] = hex_chars[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hex_chars[in[i] & 0xF];
    }
    out[in_len * 2] = '\0';
}

static int hexStringToBigInt(const char *hex, BigInt *out) {
    uint8_t buf[32];//storing in 32bytes array
    if (!hex_to_bytes(hex, buf, 32)) return 0;
    bn_read_be(buf, out); //using Trezor’s big-number functions putting the 32byte array in bigint a/b
    return 1;
}

static void bigintToHex(const BigInt *val, char out[65]) {
    uint8_t buf[32];
    bn_write_be(val, buf);
    bytes_to_hex(buf, 32, out);
}

/* ---------- Randomness Helper ---------- */
static void readRandom32(uint8_t out[32]) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open /dev/urandom\n");
        exit(1);
    }
    if (fread(out, 1, 32, f) != 32) {
        fprintf(stderr, "Error: failed to read 32 random bytes\n");
        fclose(f);
        exit(1);
    }
    fclose(f);
}

/* Generate a random BigInt in [1, order-1] */
static void randomModOrder(const BigInt *order, BigInt *out) {
    while (1) {
        uint8_t buf[32]; 
        readRandom32(buf); // Get 32 random bytes
        bn_read_be(buf, out);// Convert the 32 bytes into a BigInt
        bn_mod(out, order); // Reduce the number modulo 'order'
        if (!bn_is_zero(out))  // Ensure the result is nonzero
            break;
    }
}

/* ---------- Ephemeral Key Generation & ECDH ---------- */
typedef struct {
    BigInt priv;
    curve_point pub;
} EphemeralKey;

static void generateEphemeralKey(const ecdsa_curve *curve, EphemeralKey *key) {
    // Generate random ephemeral private key (ensuring nonzero)
    randomModOrder(&curve->order, &key->priv);
    // Public key: set to base point and multiply: pub = priv * G
    memcpy(&key->pub, &curve->G, sizeof(curve_point)); // copying the curve's base point G (which is part of the curve parameters) into key->pub.
    if (point_multiply(curve, &key->priv, &key->pub, &key->pub) != 0) {
        fprintf(stderr, "Error: point_multiply (ephemeral key generation)\n");
        exit(1);
    }
}

static void computeSharedKey(const ecdsa_curve *curve,
                             const BigInt *priv,
                             const curve_point *otherPub,
                             uint8_t out[32])
{
    curve_point shared;
    memcpy(&shared, otherPub, sizeof(shared)); //copying other's public key in shared
    if (point_multiply(curve, priv, &shared, &shared) != 0) {
        fprintf(stderr, "Error: point_multiply (ECDH)\n");
        exit(1);
    }
    uint8_t buf[32];
    bn_write_be(&shared.x, buf); //we use x coordinate here basically of the output(x,y) we get and hash it so that it does not tell about any patterns
    sha256_Raw(buf, 32, out);
}

/* ---------- XOR ---------- */
static void xorBytes(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    for (int i = 0; i < 32; i++)
        out[i] = key[i] ^ in[i];
}

/* ---------- MtA Share Computation ---------- */
/* Compute Party1's share: c = - (b * r) mod order, i.e., c = order - (b*r mod order) */
static void computeParty1Share(const BigInt *b,
                               const BigInt *r,
                               const BigInt *order,
                               BigInt *c)
{
    BigInt tmp;
    memcpy(&tmp, r, sizeof(tmp));
    bn_multiply(b, &tmp, order); // tmp = (b * r) mod order
    bn_mod(&tmp, order);
  // c = order - tmp, which is - (b*r) mod order  (−x mod n is equivalent to n−x(when x=0).)
     bn_subtract(order, &tmp, c); 
}

/* Compute Party2's share: d = b * (r + a) mod order */
static void computeParty2Share(const BigInt *b,
                               const BigInt *ra,
                               const BigInt *order,
                               BigInt *d)
{
    BigInt tmp;
    memcpy(&tmp, ra, sizeof(tmp));
    bn_multiply(b, &tmp, order); // tmp = b * (r + a) mod order
    bn_mod(&tmp, order);
    memcpy(d, &tmp, sizeof(tmp));
}

int main(void) {
    // 1. Read secret inputs a and b(256-bit number in hex format.)
    char a_hex[65], b_hex[65]; //65 for null terminator basically to prevent overflow
    printf("Enter secret a (64 hex digits):\n");
    if (scanf("%64s", a_hex) != 1) {
        fprintf(stderr, "Error reading a\n");
        return 1;
    }
    printf("Enter secret b (64 hex digits):\n");
    if (scanf("%64s", b_hex) != 1) {
        fprintf(stderr, "Error reading b\n");
        return 1;
    }
    BigInt a, b;
    if (!hexStringToBigInt(a_hex, &a)) {
        fprintf(stderr, "Invalid hex for a\n");
        return 1;
    }
    if (!hexStringToBigInt(b_hex, &b)) {
        fprintf(stderr, "Invalid hex for b\n");
        return 1;
    }

    // 2. Load the secp256k1 curve and its order
    const ecdsa_curve *curve = &secp256k1;
    BigInt order;
    memcpy(&order, &curve->order, sizeof(order));

    if (!bn_is_less(&a, &order)) {   //as 0<=a<n
        fprintf(stderr, "Error: a >= order\n");
        return 1;
    }
    if (!bn_is_less(&b, &order)) {
        fprintf(stderr, "Error: b >= order\n");
        return 1;
    }

    // 3. Generate ephemeral keys for Party1 and Party2
    EphemeralKey p1, p2;
    generateEphemeralKey(curve, &p1);
    generateEphemeralKey(curve, &p2);

    // 4. Compute ECDH shared key from both sides; they must be equal.
    uint8_t shared1[32], shared2[32];
    computeSharedKey(curve, &p1.priv, &p2.pub, shared1);
    computeSharedKey(curve, &p2.priv, &p1.pub, shared2);
    if (memcmp(shared1, shared2, 32) != 0) {
        fprintf(stderr, "Error: ECDH mismatch\n");
        return 1;
    }
    uint8_t sharedKey[32];
    memcpy(sharedKey, shared1, 32);

    // 5. MtA Step: Party1 picks random r and computes:
    //    m0 = r, m1 = (r + a) mod order, then encrypts them with XOR using sharedKey.
    BigInt r;
    randomModOrder(&order, &r);

    BigInt ra;
    memcpy(&ra, &r, sizeof(ra));//start with ra=r
    bn_add(&ra, &a);//ra=a+r
    bn_mod(&ra, &order);//doing mod

    uint8_t m0_bytes[32], m1_bytes[32];//as XOR encryption function works on raw bytes, not on BigInt types.
    bn_write_be(&r, m0_bytes);
    bn_write_be(&ra, m1_bytes);

    uint8_t m0_enc[32], m1_enc[32];
    xorBytes(sharedKey, m0_bytes, m0_enc);
    xorBytes(sharedKey, m1_bytes, m1_enc); //xor will make sure that when other party trys to do xor again with shared key then it gives them this r or r+a

    // 6. Simulate Party2 choosing m1: decrypt m1_enc to recover (r + a)
    uint8_t decrypted[32];
    xorBytes(sharedKey, m1_enc, decrypted);//sending r+a  here
    BigInt received;
    bn_read_be(decrypted, &received);

    // 7. Compute shares:
    //    Party1's share c = - (b * r) mod order
    //    Party2's share d = b * (r + a) mod order
    BigInt c, d;
    computeParty1Share(&b, &r, &order, &c);
    computeParty2Share(&b, &received, &order, &d);

    // 8. Verify: (c + d) mod order should equal (a * b) mod order
    BigInt sum;
    memcpy(&sum, &c, sizeof(sum));
    bn_addmod(&sum, &d, &order);
    bn_mod(&sum, &order);

    BigInt ab;
    memcpy(&ab, &a, sizeof(ab));
    bn_multiply(&b, &ab, &order);
    bn_mod(&ab, &order);

    if (!bn_is_equal(&sum, &ab)) {
        fprintf(stderr, "Error: shares do not sum to a*b\n");
        // For debugging
        char sum_hex[65], ab_hex[65];
        bigintToHex(&sum, sum_hex);
        bigintToHex(&ab, ab_hex);
        fprintf(stderr, "Computed sum(c+d) mod n: %s\n", sum_hex);
        fprintf(stderr, "Expected a*b mod n: %s\n", ab_hex);
        return 1;
    }

    // 9. Output the shares in hex
    char c_hex[65], d_hex[65];
    bigintToHex(&c, c_hex);
    bigintToHex(&d, d_hex);
    printf("Party1 Share (c): %s\n", c_hex);
    printf("Party2 Share (d): %s\n", d_hex);
    printf("Success: c+d = a*b mod n\n");
    return 0;
}

