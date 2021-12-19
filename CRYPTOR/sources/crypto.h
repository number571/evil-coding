#ifndef EXTCLIB_CRYPTO_H_
#define EXTCLIB_CRYPTO_H_

extern void crypto_encrypt (
	unsigned char * output,
	const unsigned char * const key,
	int ksize,
	const unsigned char * const iv,
	int vsize,
	const unsigned char * const input, 
	int isize
);

#endif /* EXTCLIB_CRYPTO_H_ */
