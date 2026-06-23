(* rsa_ffi_install.sml

   Constant-time RSA-PSS backend for the FFI build (Track 1a). Installs an
   OpenSSL/libcrypto-backed override for Rsa.signPss / Rsa.verifyPss so the
   live TLS CertificateVerify (tls.sml) and X.509 RSASSA-PSS certificate
   signature checks (x509.sml) run in constant time with respect to the
   private key, without changing those consumers (they keep calling
   Rsa.signPss / Rsa.verifyPss).

   Keys are marshalled to standard DER (SubjectPublicKeyInfo for verify,
   PKCS#8 PrivateKeyInfo for sign) using the existing Rsa encoders, then
   handed to CryptoFfi.RsaPss. The PSS salt LENGTH is preserved across the
   boundary; OpenSSL draws a fresh random salt of that length, so an
   FFI-produced signature is NOT byte-identical to the pure-SML fixed-salt
   output but verifies under both verifiers (proven in test/ffi.sml).

   Selected only by the FFI build (sources-ffi.mlb); the default build never
   loads this file and keeps the pure-SML PSS implementation. *)

structure RsaFfiInstall :> sig val install : unit -> unit end =
struct
  (* Rsa.hash -> shim hashId (0=SHA-1, 1=SHA-256, 2=SHA-512). *)
  fun hashId Rsa.SHA1   = 0
    | hashId Rsa.SHA256 = 1
    | hashId Rsa.SHA512 = 2

  fun ffiSignPss { priv, hash, salt, msg } =
    CryptoFfi.RsaPss.sign
      { pkcs8Der = Rsa.encodePkcs8Der priv
      , hashId   = hashId hash
      , saltLen  = String.size salt
      , msg      = msg }

  fun ffiVerifyPss { pub, hash, saltLen, msg, sgn } =
    CryptoFfi.RsaPss.verify
      { spkiDer = Rsa.encodeSpkiDer pub
      , hashId  = hashId hash
      , saltLen = saltLen
      , msg     = msg
      , sgn     = sgn }
      handle _ => false

  val installed = ref false
  fun install () =
    if !installed then ()
    else
      ( CryptoFfi.init ()
      ; Rsa.installPssBackend { sign = ffiSignPss, verify = ffiVerifyPss }
      ; installed := true )
end

(* Activate the constant-time backend at load time so it is in force before
   any handshake runs in the FFI build. *)
val () = RsaFfiInstall.install ()
