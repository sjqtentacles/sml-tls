#!/bin/sh
# gen.sh - Deterministically generate golden certificate fixtures for Track A2.
#
# Produces RSA-signed (PKCS#1 v1.5 with SHA-256) X.509 chains under a fixed
# seed, so the resulting DER bytes are reproducible across machines. All
# output is committed; tests read these files at runtime with no network.
#
# Layout (every chain is leaf-first DER on the wire, but stored here as PEM
# for human inspection and as DER for the test suite):
#
#   root.pem / root.der                 - self-signed root CA
#   intermediate.pem / intermediate.der - intermediate CA (pathLen=0 by default)
#   leaf.pem / leaf.der                 - server leaf, CN=www.example.com,
#                                         SAN DNS:www.example.com, *.example.com
#
#   expired-leaf.pem/.der               - leaf whose notAfter is in the past
#   wrongname-leaf.pem/.der             - leaf with SAN www.other.com only
#   untrusted-leaf.pem/.der + untrusted-root.pem/.der
#                                       - valid chain that does NOT lead to
#                                         the trusted root
#   pathlen-intermediate.pem/.der       - intermediate with pathLen=0 that
#                                         nevertheless signs another CA
#   pathlen-subca.pem/.der              - the CA signed by pathlen-intermediate
#   pathlen-leaf.pem/.der               - leaf signed by pathlen-subca
#   badsig-intermediate.der             - intermediate with one signature byte
#                                         flipped (tampered DER)
#
# Regenerate with:  sh test/fixtures/certs/gen.sh
#
# Requires openssl 3.x. Determinism comes from a fixed RANDSEED + fixed
# serials; OpenSSL's RSA keygen is deterministic given the same RNG state.

set -e
cd "$(dirname "$0")"

# Pin the RNG so key generation is reproducible on a given OpenSSL build.
SEED="sml-tls-a2-fixtures-fixed-seed-2026"
printf '%s' "$SEED" > ./.rnd.seed
RANDOPT="-rand ./.rnd.seed"

# Helper: write the ext file for a given cert type. POSIX sh, no process subs.
make_ext () {
  out="$1"
  cat > "$out"
}

# ---------------------------------------------------------------- roots
# Root CA: self-signed, CA:TRUE, no pathLen.
openssl req -x509 -new -newkey rsa:2048 -keyout root.key -out root.pem \
  -days 7300 -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles/CN=sml-tls Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  $RANDOPT >/dev/null 2>&1

# Intermediate CA: CA:TRUE, pathLen:0 (so it may sign leaves but not further CAs).
openssl req -new -newkey rsa:2048 -keyout intermediate.key -out intermediate.csr \
  -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles/CN=sml-tls Test Intermediate CA" \
  $RANDOPT >/dev/null 2>&1

make_ext intermediate.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
openssl x509 -req -in intermediate.csr -CA root.pem -CAkey root.key \
  -CAcreateserial -out intermediate.pem -days 3650 -sha256 \
  -extfile intermediate.ext >/dev/null 2>&1

# Leaf: serverAuth, CN=www.example.com, SAN www.example.com + *.example.com.
openssl req -new -newkey rsa:2048 -keyout leaf.key -out leaf.csr \
  -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles/CN=www.example.com" \
  $RANDOPT >/dev/null 2>&1

make_ext leaf.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:www.example.com,DNS:*.example.com
EOF
openssl x509 -req -in leaf.csr -CA intermediate.pem -CAkey intermediate.key \
  -CAcreateserial -out leaf.pem -days 825 -sha256 \
  -extfile leaf.ext >/dev/null 2>&1

# ---------------------------------------------------------------- expired
# Leaf that is already expired (Jan 2020 - Feb 2020).
openssl req -new -newkey rsa:2048 -keyout expired-leaf.key -out expired-leaf.csr \
  -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles/CN=www.example.com" \
  $RANDOPT >/dev/null 2>&1

make_ext expired-leaf.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:www.example.com
EOF
openssl x509 -req -in expired-leaf.csr -CA intermediate.pem -CAkey intermediate.key \
  -CAcreateserial -out expired-leaf.pem -sha256 \
  -not_before 20200101000000Z -not_after 20200201000000Z \
  -extfile expired-leaf.ext >/dev/null 2>&1

# ------------------------------------------------------- wrong hostname
openssl req -new -newkey rsa:2048 -keyout wrongname-leaf.key -out wrongname-leaf.csr \
  -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles/CN=www.other.com" \
  $RANDOPT >/dev/null 2>&1

make_ext wrongname-leaf.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:www.other.com
EOF
openssl x509 -req -in wrongname-leaf.csr -CA intermediate.pem -CAkey intermediate.key \
  -CAcreateserial -out wrongname-leaf.pem -days 825 -sha256 \
  -extfile wrongname-leaf.ext >/dev/null 2>&1

# ----------------------------------------------------------- untrusted
# A *different* self-signed root + leaf signed by it; the leaf chain does NOT
# lead to the trusted root.
openssl req -x509 -new -newkey rsa:2048 -keyout untrusted-root.key -out untrusted-root.pem \
  -days 7300 -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles-rogue/CN=sml-tls Untrusted Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  $RANDOPT >/dev/null 2>&1

openssl req -new -newkey rsa:2048 -keyout untrusted-leaf.key -out untrusted-leaf.csr \
  -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles-rogue/CN=www.example.com" \
  $RANDOPT >/dev/null 2>&1

make_ext untrusted-leaf.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:www.example.com
EOF
openssl x509 -req -in untrusted-leaf.csr -CA untrusted-root.pem -CAkey untrusted-root.key \
  -CAcreateserial -out untrusted-leaf.pem -days 825 -sha256 \
  -extfile untrusted-leaf.ext >/dev/null 2>&1

# --------------------------------------------------- pathLen violation
# pathlen-intermediate has pathLen=0 (signed by root). It then signs another
# CA (pathlen-subca: CA:TRUE), which is a violation: a pathLen=0 CA may not
# issue further CA certs. pathlen-subca then signs the final server leaf,
# so the chain leaf -> pathlen-subca -> pathlen-intermediate -> root has a CA
# below a pathLen=0 CA.
openssl req -new -newkey rsa:2048 -keyout pathlen-intermediate.key -out pathlen-intermediate.csr \
  -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles/CN=sml-tls PathLen Intermediate CA" \
  $RANDOPT >/dev/null 2>&1

make_ext pathlen-intermediate.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
openssl x509 -req -in pathlen-intermediate.csr -CA root.pem -CAkey root.key \
  -CAcreateserial -out pathlen-intermediate.pem -days 3650 -sha256 \
  -extfile pathlen-intermediate.ext >/dev/null 2>&1

# Sub-CA signed by pathlen-intermediate (this is the violation).
openssl req -new -newkey rsa:2048 -keyout pathlen-subca.key -out pathlen-subca.csr \
  -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles/CN=sml-tls PathLen Sub-CA" \
  $RANDOPT >/dev/null 2>&1

make_ext pathlen-subca.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
openssl x509 -req -in pathlen-subca.csr -CA pathlen-intermediate.pem -CAkey pathlen-intermediate.key \
  -CAcreateserial -out pathlen-subca.pem -days 3650 -sha256 \
  -extfile pathlen-subca.ext >/dev/null 2>&1

# Final leaf signed by the sub-CA.
openssl req -new -newkey rsa:2048 -keyout pathlen-leaf.key -out pathlen-leaf.csr \
  -nodes -sha256 \
  -subj "/C=US/O=sjqtentacles/CN=www.example.com" \
  $RANDOPT >/dev/null 2>&1

make_ext pathlen-leaf.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:www.example.com
EOF
openssl x509 -req -in pathlen-leaf.csr -CA pathlen-subca.pem -CAkey pathlen-subca.key \
  -CAcreateserial -out pathlen-leaf.pem -days 825 -sha256 \
  -extfile pathlen-leaf.ext >/dev/null 2>&1

# ----------------------------------------------- bad signature on intermediate
# Take a valid intermediate DER, flip one byte in the signature, write it back.
openssl x509 -in intermediate.pem -outform DER -out badsig-intermediate.der 2>/dev/null
python3 - <<'PY'
p = "badsig-intermediate.der"
with open(p, "rb") as f:
    b = bytearray(f.read())
# Flip the last byte (signature value is the trailing BIT STRING of the
# outer SEQUENCE). XOR with 0xFF is enough to break RSA verification.
b[-1] ^= 0xFF
with open(p, "wb") as f:
    f.write(b)
print("tampered", p, "len", len(b))
PY

# ----------------------------------------------- emit DER for everything
for name in root intermediate leaf expired-leaf wrongname-leaf \
           untrusted-root untrusted-leaf pathlen-intermediate \
           pathlen-subca pathlen-leaf; do
  openssl x509 -in "$name.pem" -outform DER -out "$name.der" 2>/dev/null
done

# Clean up keys + CSRs + serials + seed + ext files (not committed).
rm -f *.key *.csr *.srl .rnd.seed .rnd *.ext

echo "Generated fixtures in $(pwd)"
ls -1
