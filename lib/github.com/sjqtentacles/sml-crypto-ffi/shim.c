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
