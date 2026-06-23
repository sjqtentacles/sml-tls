fun runFfiSuites () =
  ( Harness.reset ()
  ; FfiTests.run ()
  ; Harness.run () )

fun main () =
  OS.Process.exit
    (if runFfiSuites () then OS.Process.success else OS.Process.failure)
