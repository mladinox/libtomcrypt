/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file rc4.c
  LTC_RC4 PRNG, Tom St Denis
*/

#ifdef LTC_RC4

const struct ltc_prng_descriptor rc4_prng_desc =
{
   "rc4",
   32,
   &rc4_prng_start,
   &rc4_prng_add_entropy,
   &rc4_prng_ready,
   &rc4_prng_read,
   &rc4_prng_done,
   &rc4_prng_export,
   &rc4_prng_import,
   &rc4_prng_test
};

/**
  Start the PRNG
  @param prng     [out] The PRNG state to initialize
  @return CRYPT_OK if successful
*/
int rc4_prng_start(prng_state *prng)
{
   LTC_ARGCHK(prng != NULL);
   prng->ready = 0;
   /* set entropy (key) size to zero */
   prng->rc4.s.x = 0;
   /* clear entropy (key) buffer */
   XMEMSET(&prng->rc4.s.buf, 0, 256);
   LTC_MUTEX_INIT(&prng->lock)
   return CRYPT_OK;
}

/**
  Add entropy to the PRNG state
  @param in       The data to add
  @param inlen    Length of the data to add
  @param prng     PRNG state to update
  @return CRYPT_OK if successful
*/
int rc4_prng_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   unsigned char buf[256];
   unsigned long i;
   int err;

   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(in != NULL);
   LTC_ARGCHK(inlen > 0);

   LTC_MUTEX_LOCK(&prng->lock);
   if (prng->ready) {
      /* rc4_prng_ready() was already called, do "rekey" operation */
      if ((err = rc4_keystream(&prng->rc4.s, buf, 256)) != CRYPT_OK)    goto DONE;
      for(i = 0; i < inlen; i++) buf[i % 256] ^= in[i];
      /* initialize RC4 */
      if ((err = rc4_setup(&prng->rc4.s, buf, 256)) != CRYPT_OK)        goto DONE;
      /* drop first 3072 bytes - https://en.wikipedia.org/wiki/RC4#Fluhrer.2C_Mantin_and_Shamir_attack */
      for (i = 0; i < 12; i++) rc4_keystream(&prng->rc4.s, buf, 256);
   }
   else {
      /* rc4_prng_ready() was not called yet, add entropy to the buffer */
      while (inlen--) prng->rc4.s.buf[prng->rc4.s.x++ % 256] ^= *in++;
   }
   err = CRYPT_OK;
DONE:
   LTC_MUTEX_UNLOCK(&prng->lock);
   return err;
}

/**
  Make the PRNG ready to read from
  @param prng   The PRNG to make active
  @return CRYPT_OK if successful
*/
int rc4_prng_ready(prng_state *prng)
{
   unsigned char buf[256];
   unsigned long len;
   int err, i;

   LTC_ARGCHK(prng != NULL);

   LTC_MUTEX_LOCK(&prng->lock);
   if (prng->ready) { err = CRYPT_OK; goto DONE; }
   len = MIN(prng->rc4.s.x, 256);
   if (len < 5)  { err = CRYPT_ERROR; goto DONE; }
   XMEMCPY(buf, prng->rc4.s.buf, len);
   /* initialize RC4 */
   if ((err = rc4_setup(&prng->rc4.s, buf, len)) != CRYPT_OK) goto DONE;
   /* drop first 3072 bytes - https://en.wikipedia.org/wiki/RC4#Fluhrer.2C_Mantin_and_Shamir_attack */
   for (i = 0; i < 12; i++) rc4_keystream(&prng->rc4.s, buf, 256);
   prng->ready = 1;
DONE:
   LTC_MUTEX_UNLOCK(&prng->lock);
   return err;
}

/**
  Read from the PRNG
  @param out      Destination
  @param outlen   Length of output
  @param prng     The active PRNG to read from
  @return Number of octets read
*/
unsigned long rc4_prng_read(unsigned char *out, unsigned long outlen, prng_state *prng)
{
   if (outlen == 0 || prng == NULL || out == NULL) return 0;
   LTC_MUTEX_LOCK(&prng->lock);
   if (rc4_keystream(&prng->rc4.s, out, outlen) != CRYPT_OK) outlen = 0;
   LTC_MUTEX_UNLOCK(&prng->lock);
   return outlen;
}

/**
  Terminate the PRNG
  @param prng   The PRNG to terminate
  @return CRYPT_OK if successful
*/
int rc4_prng_done(prng_state *prng)
{
   int err;
   LTC_ARGCHK(prng != NULL);
   LTC_MUTEX_LOCK(&prng->lock);
   prng->ready = 0;
   err = rc4_done(&prng->rc4.s);
   LTC_MUTEX_UNLOCK(&prng->lock);
   return err;
}

/**
  Export the PRNG state
  @param out       [out] Destination
  @param outlen    [in/out] Max size and resulting size of the state
  @param prng      The PRNG to export
  @return CRYPT_OK if successful
*/
int rc4_prng_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
   unsigned long len = 32;

   LTC_ARGCHK(prng   != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if (*outlen < len) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (rc4_prng_read(out, len, prng) != len) {
      return CRYPT_ERROR_READPRNG;
   }

   *outlen = len;
   return CRYPT_OK;
}

/**
  Import a PRNG state
  @param in       The PRNG state
  @param inlen    Size of the state
  @param prng     The PRNG to import
  @return CRYPT_OK if successful
*/
int rc4_prng_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   int err;

   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(inlen >= 32);

   if ((err = rc4_prng_start(prng)) != CRYPT_OK)                  return err;
   if ((err = rc4_prng_add_entropy(in, inlen, prng)) != CRYPT_OK) return err;
   return CRYPT_OK;
}

/**
  PRNG self-test
  @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
*/
int rc4_prng_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   prng_state st;
   unsigned char en[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                          0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                          0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                          0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                          0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32 };
   unsigned char dmp[500];
   unsigned long dmplen = sizeof(dmp);
   unsigned char out[1000];
   unsigned char t1[] = { 0xE0, 0x4D, 0x9A, 0xF6, 0xA8, 0x9D, 0x77, 0x53, 0xAE, 0x09 };
   unsigned char t2[] = { 0x9D, 0x3C, 0xC6, 0x64, 0x36, 0xB6, 0x76, 0xD5, 0xEB, 0x93 };
   unsigned char t3[] = { 0x6B, 0x6D, 0xF5, 0xCB, 0x84, 0x37, 0x8F, 0x02, 0xA2, 0x90 };

   rc4_prng_start(&st);
   rc4_prng_add_entropy(en, sizeof(en), &st);
   rc4_prng_ready(&st);
   rc4_prng_read(out, 10, &st);  /* 10 bytes for testing */
   if (compare_testvector(out, 10, t1, sizeof(t1), "RC4-PRNG", 1)) return CRYPT_FAIL_TESTVECTOR;
   rc4_prng_read(out, 500, &st);
   rc4_prng_export(dmp, &dmplen, &st);
   rc4_prng_read(out, 500, &st); /* skip 500 bytes */
   rc4_prng_read(out, 10, &st);  /* 10 bytes for testing */
   if (compare_testvector(out, 10, t2, sizeof(t2), "RC4-PRNG", 2)) return CRYPT_FAIL_TESTVECTOR;
   rc4_prng_done(&st);
   rc4_prng_import(dmp, dmplen, &st);
   rc4_prng_ready(&st);
   rc4_prng_read(out, 500, &st); /* skip 500 bytes */
   rc4_prng_read(out, 10, &st);  /* 10 bytes for testing */
   if (compare_testvector(out, 10, t3, sizeof(t3), "RC4-PRNG", 3)) return CRYPT_FAIL_TESTVECTOR;
   rc4_prng_done(&st);

   return CRYPT_OK;
#endif
}

#endif
