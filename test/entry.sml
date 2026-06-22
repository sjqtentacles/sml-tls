fun runAllSuites () =
  ( Harness.reset ()
  ; TlsTests.run ()
  ; RecordTests.run ()
  ; CertTests.run ()
  ; ExtTests.run ()
  ; Hs2Tests.run ()
  ; HardenTests.run ()
  ; Harness.run () )

fun main () =
  OS.Process.exit
    (if runAllSuites () then OS.Process.success else OS.Process.failure)
