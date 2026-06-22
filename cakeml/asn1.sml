(* asn1.sml -- CakeML port of sml-asn1 (X.690 DER encoder/decoder).

   Canonical TLV form: identifier octet, DEFINITE length (short form < 128
   else minimal long form), then contents.  INTEGER uses minimal
   two's-complement octets, OBJECT IDENTIFIER combines the first two arcs
   and base-128 encodes each subidentifier.  Decoding is strict.

   Dialect-gap fixes (see asn1_PORT_NOTES.md):
     - `datatype ... of ...` -> Haskell-style curried constructors
     - BigInt replaced by CakeML native `int` (arbitrary precision)
     - tupled basis calls (String.sub/substring/extract) made curried
     - multi-clause `fun ... | ...` rewritten with `case`
     - `SOME`/`NONE`/`valOf` -> `Some`/`None`/`Option.valOf`
     - integer `case` patterns rewritten as `if`/`else`
     - no signature ascription
*)

structure Asn1 = struct

  datatype der =
      Bool bool
    | Int int
    | Bytes string
    | BitString string
    | Null
    | Oid (int list)
    | Utf8 string
    | PrintableString string
    | Seq (der list)
    | Set (der list)
    | Context int der

  exception Asn1 string

  (* ---- universal tag numbers ---- *)
  val tBool   = 0x01
  val tInt    = 0x02
  val tBits   = 0x03
  val tOctet  = 0x04
  val tNull   = 0x05
  val tOid    = 0x06
  val tUtf8   = 0x0C
  val tSeq    = 0x10
  val tSet    = 0x11
  val tPrint  = 0x13

  val constructedBit = 0x20
  val contextClass   = 0x80

  fun chr n = String.str (Char.chr n)
  fun byteAt (s, i) = Char.ord (String.sub s i)

  (* ================= ENCODE ================= *)

  fun lenDigits n = if n = 0 then [] else lenDigits (n div 256) @ [n mod 256]

  fun encodeLen len =
    if len < 128 then chr len
    else
      let val ds = lenDigits len
      in chr (0x80 + List.length ds) ^ String.concat (List.map chr ds) end

  fun tlv (idByte, content) =
    chr idByte ^ encodeLen (String.size content) ^ content

  (* ---- INTEGER: minimal two's complement (native int) ---- *)

  fun digitsLE n =
    if n = 0 then []
    else (n mod 256) :: digitsLE (n div 256)

  fun pow2 k = if k <= 0 then 1 else 2 * pow2 (k - 1)

  fun encodeIntContent n =
    if n = 0 then chr 0
    else if n > 0 then
      let
        val be = List.rev (digitsLE n)
        val bytes = case be of
                      (b0 :: _) => if b0 >= 0x80 then 0 :: be else be
                    | [] => [0]
      in String.concat (List.map chr bytes) end
    else
      let
        fun findK k =
          if n >= ~(pow2 (8 * k - 1)) then k
          else findK (k + 1)
        val k = findK 1
        val twos = pow2 (8 * k) + n
        val be = List.rev (digitsLE twos)
        val pad = List.tabulate (k - List.length be) (fn _ => 0)
      in String.concat (List.map chr (pad @ be)) end

  (* ---- OBJECT IDENTIFIER ---- *)

  fun base128 v =
    let
      fun groupsLE n = if n < 128 then [n] else (n mod 128) :: groupsLE (n div 128)
      val be = List.rev (groupsLE v)
      val n = List.length be
      fun mark (i, xs) =
        case xs of
          [] => []
        | (x :: rest) => (if i < n - 1 then x + 0x80 else x) :: mark (i + 1, rest)
    in mark (0, be) end

  fun encodeOidContent arcs =
    case arcs of
      (a0 :: a1 :: rest) =>
        if a0 < 0 orelse a0 > 2 then raise Asn1 "OID: first arc must be 0, 1 or 2"
        else if a1 < 0 then raise Asn1 "OID: negative arc"
        else if a0 < 2 andalso a1 >= 40 then raise Asn1 "OID: second arc out of range"
        else if List.exists (fn x => x < 0) rest then raise Asn1 "OID: negative arc"
        else
          let val subs = (40 * a0 + a1) :: rest
          in String.concat (List.map chr (List.concat (List.map base128 subs))) end
    | _ => raise Asn1 "OID: needs at least two arcs"

  fun encode der =
    case der of
      Bool b => tlv (tBool, if b then chr 0xFF else chr 0x00)
    | Int n => tlv (tInt, encodeIntContent n)
    | Bytes s => tlv (tOctet, s)
    | BitString s => tlv (tBits, chr 0 ^ s)
    | Null => tlv (tNull, "")
    | Oid arcs => tlv (tOid, encodeOidContent arcs)
    | Utf8 s => tlv (tUtf8, s)
    | PrintableString s => tlv (tPrint, s)
    | Seq ds => tlv (tSeq + constructedBit, String.concat (List.map encode ds))
    | Set ds => tlv (tSet + constructedBit, String.concat (List.map encode ds))
    | Context n d =>
        if n < 0 orelse n > 30 then raise Asn1 "Context: tag out of range (0..30)"
        else tlv (contextClass + constructedBit + n, encode d)

  (* ================= DECODE ================= *)

  fun readLen (s, pos) =
    let
      val size = String.size s
      val () = if pos >= size then raise Asn1 "truncated length" else ()
      val b0 = byteAt (s, pos)
    in
      if b0 < 0x80 then (b0, pos + 1)
      else
        let val n = b0 - 0x80
        in
          if n = 0 then raise Asn1 "indefinite length not allowed in DER"
          else if pos + n >= size then raise Asn1 "truncated long-form length"
          else if byteAt (s, pos + 1) = 0 then raise Asn1 "non-minimal length (leading zero)"
          else
            let
              fun loop (i, acc) =
                if i = n then acc else loop (i + 1, acc * 256 + byteAt (s, pos + 1 + i))
              val len = loop (0, 0)
            in
              if len < 128 then raise Asn1 "non-minimal length (should be short form)"
              else (len, pos + 1 + n)
            end
        end
    end

  fun decodeIntContent s =
    let
      val len = String.size s
      val () = if len = 0 then raise Asn1 "empty INTEGER" else ()
      val b0 = byteAt (s, 0)
      val () =
        if len > 1 then
          let val b1 = byteAt (s, 1)
          in
            if (b0 = 0x00 andalso b1 < 0x80) orelse (b0 = 0xFF andalso b1 >= 0x80)
            then raise Asn1 "non-minimal INTEGER" else ()
          end
        else ()
      fun fold (i, acc) =
        if i = len then acc
        else fold (i + 1, acc * 256 + byteAt (s, i))
      val mag = fold (0, 0)
    in
      if b0 >= 0x80 then mag - pow2 (8 * len) else mag
    end

  fun decodeOidContent s =
    let
      val len = String.size s
      val () = if len = 0 then raise Asn1 "empty OID" else ()
      fun readSub (j, v, first) =
        if j = len then raise Asn1 "truncated OID subidentifier"
        else
          let
            val b = byteAt (s, j)
            val () = if first andalso b = 0x80 then raise Asn1 "non-minimal OID subidentifier" else ()
            val v2 = v * 128 + (b mod 128)
          in
            if b < 0x80 then (v2, j + 1) else readSub (j + 1, v2, False)
          end
      fun loop (i, acc) =
        if i = len then List.rev acc
        else let val (v, next) = readSub (i, 0, True) in loop (next, v :: acc) end
      val subs = loop (0, [])
    in
      case subs of
        (first :: rest) =>
          let
            val (a0, a1) =
              if first < 40 then (0, first)
              else if first < 80 then (1, first - 40)
              else (2, first - 80)
          in a0 :: a1 :: rest end
      | [] => raise Asn1 "empty OID"
    end

  fun decodeBitString s =
    let
      val len = String.size s
      val () = if len = 0 then raise Asn1 "empty BIT STRING" else ()
      val unused = byteAt (s, 0)
      val () = if unused > 7 then raise Asn1 "BIT STRING: bad unused-bit count" else ()
    in
      String.extract s 1 None
    end

  fun parseTLV (s, pos) =
    let
      val size = String.size s
      val () = if pos >= size then raise Asn1 "truncated identifier" else ()
      val id = byteAt (s, pos)
      val cls = id div 64
      val constructed = (id div 32) mod 2 = 1
      val tagnum = id mod 32
      val () = if tagnum = 31 then raise Asn1 "high-tag-number form unsupported" else ()
      val (len, cstart) = readLen (s, pos + 1)
      val cend = cstart + len
      val () = if cend > size then raise Asn1 "length exceeds input" else ()
      val content = String.substring s cstart len
      fun prim () = if constructed then raise Asn1 "primitive type must not be constructed" else ()
    in
      if cls = 0 then
        if tagnum = tBool then
          ( prim ()
          ; if len <> 1 then raise Asn1 "BOOLEAN length"
            else
              let val v = byteAt (content, 0)
              in if v = 0x00 then (Bool False, cend)
                 else if v = 0xFF then (Bool True, cend)
                 else raise Asn1 "BOOLEAN value not 0x00/0xFF"
              end )
        else if tagnum = tInt then (prim (); (Int (decodeIntContent content), cend))
        else if tagnum = tBits then (prim (); (BitString (decodeBitString content), cend))
        else if tagnum = tOctet then (prim (); (Bytes content, cend))
        else if tagnum = tNull then
          (prim (); if len <> 0 then raise Asn1 "NULL length" else (Null, cend))
        else if tagnum = tOid then (prim (); (Oid (decodeOidContent content), cend))
        else if tagnum = tUtf8 then (prim (); (Utf8 content, cend))
        else if tagnum = tPrint then (prim (); (PrintableString content, cend))
        else if tagnum = tSeq then
          if not constructed then raise Asn1 "SEQUENCE must be constructed"
          else (Seq (parseMany (s, cstart, cend)), cend)
        else if tagnum = tSet then
          if not constructed then raise Asn1 "SET must be constructed"
          else (Set (parseMany (s, cstart, cend)), cend)
        else raise Asn1 "unsupported universal tag"
      else if cls = 2 then
        if not constructed then raise Asn1 "context tag must be constructed (explicit)"
        else
          let val (inner, ipos) = parseTLV (s, cstart)
          in
            if ipos <> cend then raise Asn1 "context content is not a single TLV"
            else (Context tagnum inner, cend)
          end
      else raise Asn1 "unsupported tag class"
    end
  and parseMany (s, pos, stop) =
    if pos = stop then []
    else if pos > stop then raise Asn1 "element overruns its container"
    else let val (d, pos2) = parseTLV (s, pos) in d :: parseMany (s, pos2, stop) end

  fun decode s =
    let val (d, pos) = parseTLV (s, 0)
    in if pos <> String.size s then raise Asn1 "trailing bytes after value" else d end

  fun decodeOpt s = Some (decode s) handle _ => None

end
