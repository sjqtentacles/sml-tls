# sml-tls build
MLTON      ?= mlton
CC         ?= clang
BIN        := bin
LIBDIR     := lib/github.com/sjqtentacles/sml-tls
FFIDIR     := lib/github.com/sjqtentacles/sml-crypto-ffi
TEST_MLB   := test/sources.mlb
SRCS       := $(wildcard $(LIBDIR)/*.sml $(LIBDIR)/*.sig) \
              $(wildcard test/*.sml) $(TEST_MLB) $(LIBDIR)/sources.mlb

# --- Track 1a/1b: libsodium constant-time crypto FFI shim ---
# libsodium (Homebrew default on Apple Silicon). Override on other systems,
# e.g. SODIUM_PREFIX=/usr or =/usr/local.
SODIUM_PREFIX ?= /opt/homebrew
SODIUM_INC    := $(SODIUM_PREFIX)/include
SODIUM_LIB    := $(SODIUM_PREFIX)/lib
# OpenSSL libcrypto 3.x: constant-time AES-GCM and RSA-PSS (libsodium has
# neither AES-128-GCM nor RSA). Homebrew keg on Apple Silicon; override on
# other systems, e.g. SSL_PREFIX=/usr or =/usr/local.
SSL_PREFIX ?= /opt/homebrew/opt/openssl@3
SSL_INC    := $(SSL_PREFIX)/include
SSL_LIB    := $(SSL_PREFIX)/lib
# Shared-library extension: .dylib on macOS, .so elsewhere.
ifeq ($(shell uname -s),Darwin)
  SHLIB_EXT := dylib
else
  SHLIB_EXT := so
endif
FFI_SHIM   := $(BIN)/libsmlcryptoffi.$(SHLIB_EXT)
# MLton link flags to resolve the shim's _import symbols against the dylib
# (and libsodium + libcrypto themselves).
FFI_LINK   := -link-opt "-L$(BIN) -L$(SODIUM_LIB) -L$(SSL_LIB) -lsmlcryptoffi -lsodium -lcrypto -Wl,-rpath,$(BIN) -Wl,-rpath,$(SODIUM_LIB) -Wl,-rpath,$(SSL_LIB)"

.PHONY: all test poly test-poly all-tests ffi-shim test-ffi test-ffi-poly test-ffi-all clean

all: $(BIN)/test-mlton

$(BIN)/test-mlton: $(SRCS) | $(BIN)
	$(MLTON) -output $@ $(TEST_MLB)

test: $(BIN)/test-mlton
	$(BIN)/test-mlton

poly: $(BIN)/test-poly

$(BIN)/test-poly: $(SRCS) tools/polybuild | $(BIN)
	sh tools/polybuild -o $@ $(TEST_MLB)

test-poly: $(BIN)/test-poly
	$(BIN)/test-poly

all-tests: test test-poly

# --- FFI shim (Track 1a/1b) ---------------------------------------------
# Build the libsodium constant-time crypto shim into a shared library that
# MLton links against and Poly/ML loads at runtime via Foreign.loadLibrary.
ffi-shim: $(FFI_SHIM)

$(FFI_SHIM): $(FFIDIR)/shim.c | $(BIN)
	$(CC) -O2 -fPIC -shared -I$(SODIUM_INC) -I$(SSL_INC) $< \
	  -L$(SODIUM_LIB) -lsodium -L$(SSL_LIB) -lcrypto \
	  -Wl,-rpath,$(SSL_LIB) -o $@

# MLton FFI test: byte-identity (shim == pure-SML oracle) on RFC vectors.
test-ffi: $(FFI_SHIM) $(SRCS) test/sources-ffi-mlton.mlb \
          $(wildcard $(FFIDIR)/*.sml $(FFIDIR)/*.sig) | $(BIN)
	$(MLTON) -default-ann 'allowFFI true' $(FFI_LINK) \
	  -output $(BIN)/test-ffi-mlton test/sources-ffi-mlton.mlb
	$(BIN)/test-ffi-mlton

# Poly/ML FFI test: same suite via Foreign.loadLibrary on the shim.
test-ffi-poly: $(FFI_SHIM) $(SRCS) test/sources-ffi-poly.mlb tools/polybuild \
               $(wildcard $(FFIDIR)/*.sml $(FFIDIR)/*.sig) | $(BIN)
	SML_CRYPTO_FFI_LIB=$(FFI_SHIM) \
	  sh tools/polybuild -o $(BIN)/test-ffi-poly test/sources-ffi-poly.mlb
	SML_CRYPTO_FFI_LIB=$(FFI_SHIM) $(BIN)/test-ffi-poly

test-ffi-all: test-ffi test-ffi-poly

$(BIN):
	mkdir -p $(BIN)

clean:
	rm -rf $(BIN)
