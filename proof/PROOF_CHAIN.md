# PROOF_CHAIN.md — the complete sml-tls verification chain, spec → machine code

This document states, precisely and **honestly**, the full chain of reasoning
connecting the TLS 1.3 RFCs to executable machine code, identifying for every
link whether it is **proved in the HOL4 kernel**, **demonstrated by execution**,
or **a documented trust gap** that remains to be mechanized. It is the Track 2d
"closure" artifact: a correct demonstration plus an accurate gap statement, not
a claim of a fully-mechanized end-to-end theorem.

The companion executable demonstration is
[`cakeml/compile_chain_demo.sh`](../cakeml/compile_chain_demo.sh) (captured
output in `cakeml/compile_chain_demo.log`).

---

## The chain at a glance

```
  (1) RFC 8446 / 8439 / 5869 / 6234         normative English + test vectors
        │   [human modeling — informal]
        ▼
  (2) HOL4 spec theories                    tls_wire / tls_keyschedule /
        │                                   tls_sha256 / tls_handshake
        │   [PROVED: round-trips + RFC 8448 / NIST vectors by EVAL]
        ▼
  (3) HOL4 refinement                       tls_refinement (Track 2c):
        │                                   CakeML-shaped fns = spec fns
        │   [PROVED: equality under byte-representation map]
        │   [GAP A: hand-mirror, not translator-certified]
        ▼
  (4) CakeML source semantics               cakeml/*.sml  (semantics_prog)
        │
        │   [GAP B: compile_correct not instantiated for these programs]
        ▼
  (5) CakeML backend correctness            backendProof$compile_correct
        │                                   (CakeML v3400, PROVED upstream)
        ▼
  (6) arm8-64 machine code                  cake --target=arm8  →  .S  →  binary
                                            [DEMONSTRATED: runs, digest == NIST]
```

Links (2) and (3) are mechanized in this repo's `proof/` (5 theories, `Holmake`
green, `DB.axioms = 0`, no cheats / no custom oracles — see `PROOF_STATUS.md`).
Link (5) is mechanized **upstream in CakeML**. Links (1), (3→4) and (4→5) are
the trust boundary, made explicit below. Link (6) is **demonstrated by running
the verified compiler's output**, not by a HOL4 theorem.

---

## Link (1): RFCs → HOL4 spec  *(informal, human modeling)*

The HOL4 definitions are a hand transcription of:

* **RFC 8446** TLS 1.3 — record/handshake wire formats (§4, §5) and key
  schedule (§7.1);
* **RFC 8439** ChaCha20-Poly1305, **RFC 5869** HKDF, **RFC 6234 / FIPS 180-4**
  SHA-256 / HMAC;
* **RFC 8448** "Example Handshake Traces for TLS 1.3" — concrete byte vectors.

This is the irreducible *modeling* step: the claim "the HOL4 definitions mean
what the RFC says" is checked by review and, crucially, by **executable test
vectors** discharged inside HOL4 (see link (2)), not by a proof.

## Link (2): HOL4 spec theories  *(PROVED in HOL4)*

Four spec theories, all closed by real kernel proofs:

* **`tls_wireTheory`** — RFC 8446 §4/§5 codecs with **proved round-trips**
  `decode (encode x) = SOME (x, …)`: `decode_encode_contentType`,
  `…_handshakeType`, `…_plaintext`, `…_ciphertext`, `…_message`, `…_extensions`,
  `…_clientHello`, `…_serverHello`, `…_certificate`, `…_newSessionTicket`,
  `finished_roundtrip`, `certificateVerify_roundtrip` (some under explicit,
  honest wire-length side conditions — see `PROOF_STATUS.md`).
* **`tls_sha256Theory`** (Track 2b) — concrete computable SHA-256 / HMAC / HKDF
  (`sha256_digest_def`, `hmac_sha256_def`, `hkdf_*`) with length theorems
  (`sha256_digest_length`, `hmac_sha256_length`, `hkdf_expand_length`).
* **`tls_keyscheduleTheory`** (Track 2a/2b) — RFC 8446 §7.1 schedule, with
  **vectors discharged by `EVAL`**: NIST SHA-256 ("", "abc") and the RFC 8448
  key-schedule vectors (`rfc8448_early_secret`, `rfc8448_derived_secret`, …),
  plus `schedule_correct` / `schedule_lengths`.
* **`tls_handshakeTheory`** — handshake state machine over the wire types.

These theorems pin the spec to the RFCs *operationally*: the same functions used
in the round-trip proofs compute exactly the published NIST and RFC 8448 bytes.

## Link (3): HOL4 refinement — CakeML-shaped fns = spec fns  *(PROVED in HOL4; GAP A)*

**`tls_refinementTheory`** (Track 2c) hand-mirrors the CakeML port
(`cakeml/tls.sml`) — tuples instead of records, native `int` with `div`/`mod`
instead of `word16`/`word32`, `num list` instead of `word8 list` — and **proves**
that each CakeML-shaped codec equals the `tls_wireTheory` spec codec transported
across the byte-representation map `b2n = w2n`, `s2ns = MAP w2n`. Representative
proved theorems: `cml_contentTypeToByte_refines`, `cml_byteToContentType_refines`,
`cml_encodePlaintext_refines`, `cml_decodePlaintext_refines`,
`cml_encodeCiphertext_refines`, `cml_decodeCiphertext_refines`, and
handshake-transition refinements (`cml_startHandshake_refines_transition`,
`cml_connected_refines_idle`, …). Every theorem carries only the benign
`DISK_THM` tag.

> ### EXPANDED codec refinement coverage (this pass)
> The refined-codec set was extended beyond `contentType`/`plaintext`/
> `ciphertext`. Added and proved (no cheats, `DB.axioms = 0`, only `DISK_THM`):
> `cml_decodeCiphertext_refines` (closing the prior define-but-unrefined hole),
> and the full **encode**-direction refinements of the four structured,
> length-prefixed handshake bodies — `cml_encodeServerHello_refines`,
> `cml_encodeClientHello_refines`, `cml_encodeNewSessionTicket_refines`,
> `cml_encodeCertificate_refines` — each under the **same** honest `wf<X>`
> wire-length side condition the Track 2a round-trips use, built on proved
> structured-codec helper lemmas (`cml_word16ToBytes_refines`,
> `cml_word32ToBytes_refines`, `cml_len3_refines`, `cml_encodeExtensions_refines`,
> `cml_encodeWord16List_refines`). Composition corollaries
> (`cml_*_roundtrip_via_spec`) tie each CakeML encoder output, via injective
> `s2ns`, to a spec wire string the spec decoder inverts. The structured
> **decoders** (recursive, `Bad`-exception-driven, index-based) are **not** yet
> refined as standalone equational theorems — that direction is covered
> soundly-but-indirectly by the composition corollaries and recorded as honest
> remaining work in `PROOF_STATUS.md`. This expansion **does not** affect GAP A
> or GAP B below.

> ### GAP A — the translator-certification gap (honest)
> These equalities are proved against a **by-hand HOL4 mirror** of the CakeML
> source, *not* against an `ml_translatorLib`-produced deep embedding of the
> actual CakeML AST. The mathematically substantive half is proved (the
> CakeML-shaped arithmetic/control flow computes the spec function). What is
> **not** mechanized is the certificate "this HOL function *is* the one
> `ml_translatorLib` extracts from `cakeml/tls.sml`." Closing it requires
> re-deriving the CakeML functions through the proof-producing translator
> (`ml_translatorLib` / CF `cfTactics`) so the HOL term and the CakeML
> `semantics_prog` denotation are tied by a generated theorem. See the HONESTY
> NOTE in `tls_refinementScript.sml`.

## Link (4): CakeML source semantics

The CakeML programs in `cakeml/` (`sha256_test.cml`, `tls.sml`, …) have a formal
source-level semantics `semantics_prog s env prog` in CakeML's `semantics`
theory. Spanning link (3)→(4) is exactly GAP A: connecting the HOL functions of
`tls_refinementTheory` to this `semantics_prog` denotation.

## Link (5): CakeML backend correctness — `compile_correct`  *(PROVED upstream; GAP B to instantiate)*

The bracketed backend step is the CakeML compiler's verified
backend-correctness theorem. From
`cakeml/compiler/backend/proofs/backendProofScript.sml` (CakeML v3400):

* **`compile_correct`** (line 4146) — the headline theorem;
* **`compile_correct'`** (line 3270) — the general form (with eval-state and an
  explicit space-safety side-goal) from which `compile_correct` is derived;
* related: `compile_correct_is_safe_for_space`, `compile_correct_eval`.

The statement of `compile_correct` (verbatim shape):

```
⊢ compile (asm_conf:'a asm_config) (c:config) prog = SOME (bytes,bitmaps,c') ⇒
   let (s,env) = THE (prim_sem_env (ffi:'ffi ffi_state)) in
   ¬semantics_prog s env prog Fail ∧
   backend_config_ok asm_conf c ∧ mc_conf_ok mc ∧ mc_init_ok asm_conf c mc ∧
   installed bytes cbspace bitmaps data_sp c'.lab_conf.ffi_names
        (heap_regs c.stack_conf.reg_names) mc c'.lab_conf.shmem_extra ms ⇒
     machine_sem (mc:(α,β,γ) machine_config) ffi ms ⊆
       extend_with_resource_limit (semantics_prog s env prog)
```

**Hypotheses, informally.** *If* the verified backend `compile` produces machine
code `bytes`/`bitmaps` for source `prog`, *and*

1. `prog` does not diverge to `Fail` under the prim semantic environment
   (`¬semantics_prog s env prog Fail`);
2. the backend config is well-formed (`backend_config_ok`) and the target
   machine config is OK / correctly initialized (`mc_conf_ok`, `mc_init_ok`);
3. the produced bytes are actually `installed` in the machine state `ms`
   (FFI names, heap registers, bitmaps, shared-memory all matching),

*then* every behavior of the **machine** (`machine_sem mc ffi ms`) is a behavior
of the **source program** (`semantics_prog s env prog`), modulo
`extend_with_resource_limit` (the machine may additionally run out of
stack/heap). In short: **the compiled machine code refines the CakeML source
semantics.** This is the link that carries link (4)'s source-level meaning down
to link (6)'s machine code.

> ### GAP B — instantiating `compile_correct` for our programs (honest)
> `compile_correct` is **proved upstream**, but it is a *universally
> quantified* statement about an arbitrary `prog` and its `compile` output. To
> mechanize link (4)→(6) for *our* code we must, inside HOL4:
> 1. obtain the deep-embedded CakeML AST `prog` for `cakeml/sha256_test.cml`
>    (via `ml_translatorLib`, which also closes GAP A);
> 2. **evaluate the in-logic compiler** `compile asm_conf c prog = SOME (…)` for
>    the arm8 config (the same computation the `cake` binary performs, but as a
>    HOL theorem — the "compiler-in-the-logic" / bootstrap evaluation);
> 3. discharge the side conditions (`backend_config_ok` for the arm8 config,
>    `mc_conf_ok` / `mc_init_ok`, the `installed` predicate for the produced
>    bytes, and `¬… Fail`, the last following from translator type-safety);
> 4. compose with links (2)+(3) so that `semantics_prog … prog` is known to
>    compute the proven-correct digest, yielding a single theorem: *the machine
>    code's observable output is the spec digest.*
>
> None of steps 1–4 are done in this repo. This is the **documented trust gap**
> for the backend link: we rely on the *verified `cake` binary* to have
> performed `compile` faithfully, rather than on an in-logic `compile`
> evaluation theorem.

## Link (6): machine code  *(DEMONSTRATED by execution)*

`cakeml/compile_chain_demo.sh` feeds `cakeml/sha256_test.cml` (the source whose
spec-refinement is link (3)) to the **cached verified `cake` compiler**
(`/tmp/cake-arm8-64/cake`, CakeML v3400), emitting arm8-64 machine code
(`.cake.S`), assembling+linking it with `clang` against the CakeML FFI shim into
a native binary, running it, and checking the output **byte-for-byte against the
known NIST FIPS 180-4 digests**:

| input | machine-code output | NIST reference | match |
|---|---|---|---|
| `""` | `e3b0c442…7852b855` | `e3b0c442…7852b855` | ✓ |
| `"abc"` | `ba7816bf…f20015ad` | `ba7816bf…f20015ad` | ✓ |
| 56-byte vector | `248d6a61…19db06c1` | `248d6a61…19db06c1` | ✓ |

The host is arm64 macOS and `cake` targets arm8-64 (same ISA), so a **runnable
native binary** was produced — no cross-target caveat applied. This is the
empirical realization of link (5): the verified compiler's machine-code output
computes exactly the digest the HOL4 spec proves correct.

---

## Summary: what is proved vs. trusted

| link | status |
|---|---|
| (1) RFC → HOL4 spec | **trusted modeling**, checked by executable NIST / RFC 8448 vectors |
| (2) HOL4 spec round-trips + vectors | **PROVED** in HOL4 (no cheats, `DB.axioms = 0`) |
| (3) refinement: CakeML-shaped = spec | **PROVED** in HOL4, *minus* GAP A (hand-mirror, not translator-certified) |
| (3→4) HOL fn ↔ CakeML `semantics_prog` | **GAP A** — needs `ml_translatorLib` certificate |
| (5) `compile_correct` backend theorem | **PROVED upstream** (CakeML v3400) |
| (4→6) instantiate `compile_correct` for our prog | **GAP B** — needs in-logic `compile` eval + side conditions |
| (6) machine code computes the digest | **DEMONSTRATED** by running verified-compiler output (matches NIST) |

**To fully mechanize the composition** it remains to: run `cakeml/*.sml` through
`ml_translatorLib` to obtain certified deep embeddings (closing GAP A), evaluate
`compile` in-logic for the arm8 config and discharge `compile_correct`'s side
conditions (closing GAP B), and chain the result with the link-(2)/(3) spec
theorems. Building the entire CakeML compiler proof in HOL4 is multi-day
frontier work and was deliberately **not** attempted here. What Track 2d
delivers is the precise statement of those two remaining gaps plus a reproducible
demonstration that the verified compiler, on the spec-refined source, emits
machine code whose output equals the proven-correct NIST digests.
