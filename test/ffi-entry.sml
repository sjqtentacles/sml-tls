(* ffi-entry.sml

   Entry point for the constant-time FFI build (test-ffi / test-ffi-poly).
   Runs BOTH:
     1. the cross-implementation byte-identity vectors (FfiTests) that prove
        CryptoFfi == the pure-SML oracle on RFC/NIST vectors, and
     2. the full TLS handshake / record / cert / extension / hardening /
        zeroize suite, which under this build is wired through the FFI seam
        (sources-ffi.mlb): AES-GCM record protection and RSA-PSS
        CertificateVerify run through OpenSSL libcrypto, and key zeroing
        through sodium_memzero. This exercises the constant-time primitives
        end to end, not just the standalone vectors.

   The Poly/ML build (tools/polybuild) exports this `main`; the MLton build
   calls it via main.sml. *)

fun runFfiSuites () =
  ( Harness.reset ()
  ; FfiTests.run ()
  ; TlsTests.run ()
  ; RecordTests.run ()
  ; CertTests.run ()
  ; ExtTests.run ()
  ; Hs2Tests.run ()
  ; HardenTests.run ()
  ; ZeroizeTests.run ()
  ; Harness.run () )

fun main () =
  OS.Process.exit
    (if runFfiSuites () then OS.Process.success else OS.Process.failure)
