// code from github.com/number571/extclib.git

#include <stdint.h>
#include <string.h>

#include "crypto.h"

static void crypto_hash (
	unsigned char output[32],
	const unsigned char * const input, 
	int size
);
static int _entropy(uint8_t *output, int size);
static void _xor (
	uint8_t *output,
	uint8_t *input,
	int size
);
static void _speck (
	uint64_t output[2],
	const uint64_t input[2],
	const uint64_t key[2]
);
static void _speck_ofb (
	unsigned char * output,
	int size,
	uint64_t iv[2],
	const uint64_t key[2]
);

static uint64_t _join_8bits_to_64bits(uint8_t * b8);
static void _split_64bits_to_8bits(uint64_t b64, uint8_t * b8);

// CIPHER(Speck-OFB)
extern void crypto_encrypt (
	unsigned char * output,
	const unsigned char * const key,
	int ksize,
	const unsigned char * const iv,
	int vsize,
	const unsigned char * const input, 
	int isize
) {
	const int HSIZE = 32; // 256bit

	uint8_t buffer[HSIZE];
	uint64_t mainkey[2];
	uint64_t mainiv[2];

	crypto_hash(buffer, key, ksize);
	mainkey[0] = _join_8bits_to_64bits(buffer);
	mainkey[1] = _join_8bits_to_64bits(buffer+8);

	crypto_hash(buffer, iv, vsize);
	mainiv[0] = _join_8bits_to_64bits(buffer);
	mainiv[1] = _join_8bits_to_64bits(buffer+8);

	for (int i = 0; i < isize; i += HSIZE) {
		_speck_ofb(buffer, HSIZE, mainiv, mainkey);
		_xor(output+i, buffer, 
			(i+HSIZE >= isize) ? (isize-i) : (HSIZE));
	}
}

// HASH(Speck-MDC-2)
static void crypto_hash (
	unsigned char output[32],
	const unsigned char * const input, 
	int size
) {
	const int HSIZE = 32; // 256bit
	const int BSIZE = 16; // 128bit

	uint64_t G[2] = {0x5252525252525252, 0x5252525252525252};
	uint64_t H[2] = {0x2525252525252525, 0x2525252525252525};

	uint8_t buffer[HSIZE];
	uint64_t A[2], B[2];
	uint64_t M[2];

	for (int i = 0; i < size; i += BSIZE) {
		if (i+BSIZE >= size) {
			memcpy(buffer, input, size-i);
			memset(buffer+(size-i), 0x01, BSIZE-(size-i));
		} else {
			memcpy(buffer, input, BSIZE);
		}

		M[0] = _join_8bits_to_64bits(buffer);
		M[1] = _join_8bits_to_64bits(buffer+8);

		_speck(A, M, G);
		_speck(B, M, H);

		A[0] ^= M[0]; A[1] ^= M[1];
		B[0] ^= M[0]; B[1] ^= M[1];

		G[0] = B[0]; G[1] = A[1];
		H[0] = A[0]; H[1] = B[1];
	}

	_split_64bits_to_8bits(G[0], output);
	_split_64bits_to_8bits(G[1], output+8);
	_split_64bits_to_8bits(H[0], output+16);
	_split_64bits_to_8bits(H[1], output+24);
}

static void _xor (
	uint8_t *output,
	uint8_t *input,
	int size
) {
	for (int i = 0; i < size; ++i) {
		output[i] ^= input[i];
	}
}

#define ROR(x, r) ((x >> r) | (x << (64 - r)))
#define ROL(x, r) ((x << r) | (x >> (64 - r)))
#define R(x, y, k) (x = ROR(x, 8), x += y, x ^= k, y = ROL(y, 3), y ^= x)
#define ROUNDS 32

static void _speck (
	uint64_t output[2],
	const uint64_t input[2],
	const uint64_t key[2]
) {
	uint64_t y = input[0], x = input[1], b = key[0], a = key[1];

	R(x, y, b);
	for (int i = 0; i < ROUNDS - 1; i++) {
		R(a, b, i);
		R(x, y, b);
	}

	output[0] = y;
	output[1] = x;
}

static void _speck_ofb (
	unsigned char * output,
	int size,
	uint64_t iv[2],
	const uint64_t key[2]
) {
	const int BSIZE = 16; // 128bit

	uint8_t buffer[BSIZE];

	for (int i = 0; i < size; i += BSIZE) { 
		_speck(iv, iv, key);
		_split_64bits_to_8bits(iv[0], buffer);
		_split_64bits_to_8bits(iv[1], buffer+8);
		memcpy(output+i, buffer, 
			(i+BSIZE >= size) ? (size-i) : (BSIZE));
	}
}

static uint64_t _join_8bits_to_64bits(uint8_t * b8) {
	uint64_t b64;
	for (uint8_t *p = b8; p < b8 + 8; ++p) {
		b64 = (b64 << 8) | *p;
	}
	return b64;
}

static void _split_64bits_to_8bits(uint64_t b64, uint8_t * b8) {
	for (size_t i = 0; i < 8; ++i) {
		b8[i] = (uint8_t)(b64 >> ((7 - i) * 8));
	}
}
