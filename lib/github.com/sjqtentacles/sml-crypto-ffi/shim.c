/* shim.c -- constant-time crypto shim over libsodium.
 *
 * Track 1a (practical security): the pure-SML crypto in sml-x25519 /
 * sml-chacha20 / sml-aead does field arithmetic with data-dependent
 * branches and IntInf operations whose timing leaks secret material. This
 * shim exposes a few flat C entry points wrapping libsodium's audited,
 * constant-time implementations so sml-tls can use them as a drop-in,
 * byte-identical replacement for the highest-value primitives:
 *
 *   - X25519 (RFC 7748)                  : crypto_scalarmult_curve25519*
 *   - ChaCha20-Poly1305 IETF (RFC 8439)  : crypto_aead_chacha20poly1305_ietf_*
 *   - memory zeroing (Track 1b)          : sodium_memzero
 *
 * All buffers are passed as raw byte pointers + explicit lengths so both
 * MLton's `_import` and Poly/ML's `Foreign` can call these with simple,
 * portable C types (pointers and ints) -- no `unsigned long long *`
 * out-parameters or NULL `nsec` arguments leak into the SML FFI surface.
 *
 * Build (see the project Makefile): compiled to a shared library that
 * MLton links via -link-opt and Poly/ML loads via Foreign.loadLibrary.
 */
#include <sodium.h>
#include <string.h>

/* OpenSSL libcrypto (3.x): constant-time AES-GCM and RSA-PSS. libsodium has
 * neither AES-128-GCM nor RSA, so the AES-GCM and RSA-PSS entry points below
 * wrap OpenSSL's EVP interface. See the project Makefile for the -lcrypto
 * include/link flags. */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/* Initialise libsodium. Idempotent; returns 0 on success, 1 if already
 * initialised, -1 on failure. Callers should invoke this once before any
 * other entry point. */
int sml_sodium_init(void) {
  return sodium_init();
}

/* X25519 scalar multiplication (RFC 7748).
 *   out[32] = X25519(scalar[32], point[32])
 * libsodium clamps `scalar` internally exactly as RFC 7748 specifies, so
 * this matches the pure-SML X25519.dh on clamped/unclamped inputs alike.
 * Returns 0 on success, -1 if the result is the all-zero point. */
int sml_x25519(unsigned char *out,
               const unsigned char *scalar,
               const unsigned char *point) {
  return crypto_scalarmult_curve25519(out, scalar, point);
}

/* X25519 base-point multiplication: out[32] = X25519(scalar[32], 9).
 * Returns 0 on success. */
int sml_x25519_base(unsigned char *out, const unsigned char *scalar) {
  return crypto_scalarmult_curve25519_base(out, scalar);
}

/* ChaCha20-Poly1305 (IETF, RFC 8439) AEAD seal.
 *   c   : output buffer, must have room for mlen + 16 (ciphertext||tag)
 *   m   : plaintext, length mlen
 *   ad  : associated data, length adlen (may be empty)
 *   npub: 12-byte nonce
 *   k   : 32-byte key
 * Returns the number of bytes written to `c` (mlen + 16), or -1 on error. */
int sml_chacha20poly1305_seal(unsigned char *c,
                              const unsigned char *m, int mlen,
                              const unsigned char *ad, int adlen,
                              const unsigned char *npub,
                              const unsigned char *k) {
  unsigned long long clen = 0;
  if (mlen < 0 || adlen < 0) return -1;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          c, &clen,
          m, (unsigned long long) mlen,
          ad, (unsigned long long) adlen,
          NULL, npub, k) != 0)
    return -1;
  return (int) clen;
}

/* ChaCha20-Poly1305 (IETF, RFC 8439) AEAD open.
 *   m   : output buffer, must have room for clen - 16
 *   c   : ciphertext||tag, length clen (must be >= 16)
 *   ad  : associated data, length adlen
 *   npub: 12-byte nonce
 *   k   : 32-byte key
 * Returns the plaintext length (clen - 16) on success, or -1 if the tag
 * does not verify / input is too short. */
int sml_chacha20poly1305_open(unsigned char *m,
                              const unsigned char *c, int clen,
                              const unsigned char *ad, int adlen,
                              const unsigned char *npub,
                              const unsigned char *k) {
  unsigned long long mlen = 0;
  if (clen < 16 || adlen < 0) return -1;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          m, &mlen, NULL,
          c, (unsigned long long) clen,
          ad, (unsigned long long) adlen,
          npub, k) != 0)
    return -1;
  return (int) mlen;
}

/* Best-effort secure zeroing the optimizer cannot elide (Track 1b).
 * Zeroes n bytes at p. */
void sml_memzero(unsigned char *p, int n) {
  if (n > 0) sodium_memzero(p, (size_t) n);
}

/* --- AES-GCM (OpenSSL EVP, constant-time) ------------------------------
 * The cipher (AES-128 vs AES-256) is selected by the key length: 16 bytes
 * -> EVP_aes_128_gcm, 32 bytes -> EVP_aes_256_gcm. The IV is variable
 * length (12 bytes for TLS). Output layout matches the pure-SML AesGcm
 * oracle and the ChaCha20 shim: ciphertext followed by a 16-byte tag. */

static const EVP_CIPHER *sml_gcm_for_keylen(int klen) {
  if (klen == 16) return EVP_aes_128_gcm();
  if (klen == 32) return EVP_aes_256_gcm();
  return NULL;
}

/* AES-GCM seal.
 *   c   : output buffer, must have room for mlen + 16 (ciphertext||tag)
 *   m   : plaintext, length mlen
 *   ad  : associated data, length adlen (may be empty)
 *   iv  : nonce, length ivlen (12 for TLS)
 *   k   : key, length klen (16 or 32)
 * Writes ct||tag(16); returns mlen + 16, or -1 on error. */
int sml_aesgcm_seal(unsigned char *c,
                    const unsigned char *m, int mlen,
                    const unsigned char *ad, int adlen,
                    const unsigned char *iv, int ivlen,
                    const unsigned char *k, int klen) {
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx = NULL;
  int outl = 0, tmpl = 0, ok = -1;
  if (mlen < 0 || adlen < 0 || ivlen <= 0) return -1;
  cipher = sml_gcm_for_keylen(klen);
  if (cipher == NULL) return -1;
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return -1;
  if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL) != 1) goto done;
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, k, iv) != 1) goto done;
  if (adlen > 0) {
    if (EVP_EncryptUpdate(ctx, NULL, &tmpl, ad, adlen) != 1) goto done;
  }
  if (EVP_EncryptUpdate(ctx, c, &outl, m, mlen) != 1) goto done;
  if (EVP_EncryptFinal_ex(ctx, c + outl, &tmpl) != 1) goto done;
  outl += tmpl;
  /* Append the 16-byte authentication tag after the ciphertext. */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, c + outl) != 1) goto done;
  ok = outl + 16;
done:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

/* AES-GCM open.
 *   m   : output buffer, must have room for clen - 16
 *   c   : ciphertext||tag, length clen (must be >= 16)
 *   ad  : associated data, length adlen
 *   iv  : nonce, length ivlen
 *   k   : key, length klen (16 or 32)
 * Verifies the tag; returns clen - 16 on success, or -1 if the tag does
 * not verify / input is too short. */
int sml_aesgcm_open(unsigned char *m,
                    const unsigned char *c, int clen,
                    const unsigned char *ad, int adlen,
                    const unsigned char *iv, int ivlen,
                    const unsigned char *k, int klen) {
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx = NULL;
  int outl = 0, tmpl = 0, mlen, ok = -1;
  if (clen < 16 || adlen < 0 || ivlen <= 0) return -1;
  mlen = clen - 16;
  cipher = sml_gcm_for_keylen(klen);
  if (cipher == NULL) return -1;
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return -1;
  if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL) != 1) goto done;
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, k, iv) != 1) goto done;
  if (adlen > 0) {
    if (EVP_DecryptUpdate(ctx, NULL, &tmpl, ad, adlen) != 1) goto done;
  }
  if (EVP_DecryptUpdate(ctx, m, &outl, c, mlen) != 1) goto done;
  /* Set the expected tag (the trailing 16 bytes) before finalising. */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                          (void *)(c + mlen)) != 1) goto done;
  /* EVP_DecryptFinal_ex returns <= 0 iff the tag does not verify. */
  if (EVP_DecryptFinal_ex(ctx, m + outl, &tmpl) != 1) goto done;
  ok = outl + tmpl;
done:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

/* --- RSA-PSS (OpenSSL EVP, constant-time) ------------------------------
 * Keys cross the FFI as standard DER: SubjectPublicKeyInfo for verify,
 * PKCS#8 PrivateKeyInfo for sign. hashId selects the digest:
 *   0 -> SHA-1, 1 -> SHA-256, 2 -> SHA-512.
 * saltLen is the PSS salt length in bytes. */

static const EVP_MD *sml_md_for_id(int hashId) {
  switch (hashId) {
    case 0: return EVP_sha1();
    case 1: return EVP_sha256();
    case 2: return EVP_sha512();
    default: return NULL;
  }
}

/* RSA-PSS verify.
 *   spki   : SubjectPublicKeyInfo DER, length spkilen
 *   msg    : message, length msglen
 *   sig    : signature, length siglen
 * Returns 1 if the signature is valid, 0 if invalid, -1 on error. */
int sml_rsa_pss_verify(const unsigned char *spki, int spkilen,
                       int hashId, int saltLen,
                       const unsigned char *msg, int msglen,
                       const unsigned char *sig, int siglen) {
  const unsigned char *p = spki;
  const EVP_MD *md;
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *mdctx = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  int rc, ret = -1;
  if (spkilen < 0 || msglen < 0 || siglen < 0) return -1;
  md = sml_md_for_id(hashId);
  if (md == NULL) return -1;
  pkey = d2i_PUBKEY(NULL, &p, (long) spkilen);
  if (pkey == NULL) return -1;
  mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) goto done;
  if (EVP_DigestVerifyInit(mdctx, &pctx, md, NULL, pkey) != 1) goto done;
  if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) goto done;
  if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLen) != 1) goto done;
  rc = EVP_DigestVerify(mdctx, sig, (size_t) siglen, msg, (size_t) msglen);
  /* 1 = valid, 0 = invalid signature, <0 = error. */
  ret = (rc == 1) ? 1 : (rc == 0) ? 0 : -1;
done:
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return ret;
}

/* RSA-PSS sign.
 *   out    : output buffer, capacity outcap (>= modulus length)
 *   pkcs8  : PKCS#8 PrivateKeyInfo DER, length pkcs8len
 *   msg    : message, length msglen
 * Writes the signature to out; returns the signature length, or -1 on
 * error (including out too small). */
int sml_rsa_pss_sign(unsigned char *out, int outcap,
                     const unsigned char *pkcs8, int pkcs8len,
                     int hashId, int saltLen,
                     const unsigned char *msg, int msglen) {
  const unsigned char *p = pkcs8;
  const EVP_MD *md;
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *mdctx = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  size_t siglen = 0;
  int ret = -1;
  if (pkcs8len < 0 || msglen < 0 || outcap < 0) return -1;
  md = sml_md_for_id(hashId);
  if (md == NULL) return -1;
  pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, (long) pkcs8len);
  if (pkey == NULL) return -1;
  mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) goto done;
  if (EVP_DigestSignInit(mdctx, &pctx, md, NULL, pkey) != 1) goto done;
  if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) goto done;
  if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLen) != 1) goto done;
  /* First call: query the signature length. */
  if (EVP_DigestSign(mdctx, NULL, &siglen, msg, (size_t) msglen) != 1) goto done;
  if ((int) siglen > outcap) goto done;
  if (EVP_DigestSign(mdctx, out, &siglen, msg, (size_t) msglen) != 1) goto done;
  ret = (int) siglen;
done:
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return ret;
}
