fun runAllSuites () =
  ( Harness.reset ()
  ; TlsTests.run ()
  ; RecordTests.run ()
  ; CertTests.run ()
  ; ExtTests.run ()
  ; Harness.run () )

fun main () =
  OS.Process.exit
    (if runAllSuites () then OS.Process.success else OS.Process.failure)
