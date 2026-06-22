# sml-kdf → CakeML Port Notes

## Summary

Ported the **HKDF (RFC 5869)** portion of `sml-kdf` to the CakeML subset,
over HMAC-SHA-256 (RFC 2104) and SHA-256 (FIPS 180-4). All three RFC 5869
SHA-256 test cases pass byte-for-byte on the pinned `cake` v3400, both the
`extract` (PRK) and the `derive`/`expand` (OKM) directions, plus an RFC 4231
HMAC-SHA-256 sanity vector.

## Scope decision

The brief scopes L2 `sml-kdf` to **HKDF**. The original `kdf.sml` also
contains **scrypt** (RFC 7914) with a Salsa20/8 core and a SHA-512 PRF path.
Those are intentionally **not** ported at this layer:

- scrypt's Salsa20/8 core is `Word32`-heavy (same `add32`/`rotl` shim as the
  L0 ciphers) and depends on PBKDF2-HMAC-SHA256; it is a sizeable separate
  unit and not part of the HKDF deliverable.
- the `HmacSha512` PRF needs a SHA-512 port (not in the L0 tower).

`hkdf{Extract,Expand,Derive}` here are SHA-256-only. This is honestly noted in
the source header.

## Dialect-gap fixes applied

1. **Records → tuples.** `extract prf {salt, ikm}` → `hkdfExtract (salt, ikm)`,
   `expand prf {prk, info, len}` → `hkdfExpand (prk, info, len)`,
   `derive prf {salt, ikm, info, len}` → `hkdfDerive (salt, ikm, info, len)`.
2. **Multi-clause `fun ... | ...` for the PRF dispatch removed.** The
   `hashLen HmacSha256 = 32 | hashLen HmacSha512 = 64` and
   `hmac HmacSha256 = … | …` clauses collapsed to a SHA-256-only constant /
   call (see scope decision).
3. **Nested `structure Hkdf` inside `structure Kdf` flattened** to top-level
   `hkdf*` functions in `Kdf` (keeps the surface minimal; CakeML supports
   nested structures but the abstraction added nothing here).
4. **HMAC `Word` ops → `Word8`.** The original `xorByte` used `Word.xorb` /
   `Word.fromInt` / `Word.toInt`; rewritten with `Word8`. `String.map` →
   `String.translate` (CakeML's `char -> char` map is `String.translate`).
   The doubly-shadowed `val k0 = … val k0 = …` was renamed `k0a`/`k0`.
5. **Tupled basis calls made curried** (`String.sub`, `String.substring`,
   `List.tabulate`) — reused verbatim from the verified `cakeml/sha256.sml`.
6. **No signature ascription** (`:> KDF`, `:> HMAC` dropped).

## Test vectors (all PASS)

- RFC 5869 TC1 (22-byte IKM, 13-byte salt, 10-byte info, L=42): PRK + OKM.
- RFC 5869 TC2 (80-byte IKM/salt/info, L=82): PRK + OKM (multi-block expand).
- RFC 5869 TC3 (zero-length salt and info, L=42): PRK + OKM (default-salt path).
- RFC 4231 HMAC-SHA-256 TC1 ("Hi There") sanity check.

7/7 PASS, `ALL PASS`.

## Files

- `cakeml/kdf.sml` — ported library (Sha256 + Hmac + Kdf/HKDF)
- `cakeml/kdf_test.cml` — inlined source + RFC 5869 vector driver
- `cakeml/kdf_PORT_NOTES.md` — this file
