(* pem.sml -- CakeML port of sml-pem (RFC 7468) over Base64 (RFC 4648).

   Base64 (from the vendored sml-codec) is inlined here since the CakeML
   tower has no separate base64 port; Pem builds on it.

   Records are unavailable in CakeML, so the original record-based API
   (`{label, der}`) is represented as the tuple `(label, der)`.

   Dialect-gap fixes (see pem_PORT_NOTES.md):
     - records -> tuples
     - multi-clause `fun ... | ...` -> single clause + `case`
     - tupled basis calls (Vector.sub/String.sub/substring) made curried
     - `SOME`/`NONE` -> `Some`/`None`, `true`/`false` -> `True`/`False`
     - char comparisons curried (`Char.>= c #"A"`)
     - no signature ascription
*)

structure Base64 = struct
  val stdAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  val urlAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

  fun encodeWith alpha pad s =
    let
      val a = Vector.fromList (String.explode alpha)
      fun ch i = Vector.sub a i
      val bytes = String.explode s
      fun go cs acc =
        case cs of
            [] => List.rev acc
          | [c0] =>
              let
                val b0 = Char.ord c0
                val e0 = ch (b0 div 4)
                val e1 = ch ((b0 mod 4) * 16)
              in
                List.rev (if pad then #"=" :: #"=" :: e1 :: e0 :: acc
                          else e1 :: e0 :: acc)
              end
          | [c0, c1] =>
              let
                val b0 = Char.ord c0
                val b1 = Char.ord c1
                val e0 = ch (b0 div 4)
                val e1 = ch ((b0 mod 4) * 16 + b1 div 16)
                val e2 = ch ((b1 mod 16) * 4)
              in
                List.rev (if pad then #"=" :: e2 :: e1 :: e0 :: acc
                          else e2 :: e1 :: e0 :: acc)
              end
          | c0 :: c1 :: c2 :: rest =>
              let
                val b0 = Char.ord c0
                val b1 = Char.ord c1
                val b2 = Char.ord c2
                val e0 = ch (b0 div 4)
                val e1 = ch ((b0 mod 4) * 16 + b1 div 16)
                val e2 = ch ((b1 mod 16) * 4 + b2 div 64)
                val e3 = ch (b2 mod 64)
              in
                go rest (e3 :: e2 :: e1 :: e0 :: acc)
              end
    in
      String.implode (go bytes [])
    end

  fun encode s = encodeWith stdAlpha True s
  fun encodeUrl s = encodeWith urlAlpha False s

  fun deval c =
    if Char.>= c #"A" andalso Char.<= c #"Z" then Some (Char.ord c - Char.ord #"A")
    else if Char.>= c #"a" andalso Char.<= c #"z" then Some (Char.ord c - Char.ord #"a" + 26)
    else if Char.>= c #"0" andalso Char.<= c #"9" then Some (Char.ord c - Char.ord #"0" + 52)
    else if Char.= c #"+" orelse Char.= c #"-" then Some 62
    else if Char.= c #"/" orelse Char.= c #"_" then Some 63
    else None

  fun decode s =
    let
      val raw = List.filter (fn c => not (Char.= c #"=")) (String.explode s)
      fun collect cs acc =
        case cs of
            [] => Some (List.rev acc)
          | c :: rest =>
              (case deval c of Some v => collect rest (v :: acc) | None => None)
    in
      case collect raw [] of
          None => None
        | Some vals =>
            let
              fun go vs acc =
                case vs of
                    [] => Some (List.rev acc)
                  | [_] => None
                  | [v0, v1] =>
                      let val b0 = v0 * 4 + v1 div 16
                      in Some (List.rev (Char.chr b0 :: acc)) end
                  | [v0, v1, v2] =>
                      let
                        val b0 = v0 * 4 + v1 div 16
                        val b1 = (v1 mod 16) * 16 + v2 div 4
                      in Some (List.rev (Char.chr b1 :: Char.chr b0 :: acc)) end
                  | v0 :: v1 :: v2 :: v3 :: rest =>
                      let
                        val b0 = v0 * 4 + v1 div 16
                        val b1 = (v1 mod 16) * 16 + v2 div 4
                        val b2 = (v2 mod 4) * 64 + v3
                      in go rest (Char.chr b2 :: Char.chr b1 :: Char.chr b0 :: acc) end
            in
              case go vals [] of
                  Some cs => Some (String.implode cs)
                | None => None
            end
    end
end

structure Pem = struct
  exception Pem string

  val beginPre = "-----BEGIN "
  val endPre   = "-----END "
  val suffix   = "-----"
  val newline  = "\n"

  (* Split a Base64 string into chunks of at most 64 columns. *)
  fun chunk64 s =
    let
      val n = String.size s
      fun go i acc =
        if i >= n then List.rev acc
        else
          let val len = if n - i < 64 then n - i else 64
          in go (i + len) (String.substring s i len :: acc) end
    in
      go 0 []
    end

  (* (label, der) -> PEM text *)
  fun encode (label, der) =
    let
      val body = chunk64 (Base64.encode der)
      val lines =
        (beginPre ^ label ^ suffix) :: body @ [endPre ^ label ^ suffix]
    in
      String.concat (List.map (fn l => l ^ newline) lines)
    end

  fun boundaryLabel pre line =
    let
      val plen = String.size pre
      val slen = String.size suffix
    in
      if String.size line >= plen + slen
         andalso String.isPrefix pre line
         andalso String.isSuffix suffix line
      then Some (String.substring line plen (String.size line - plen - slen))
      else None
    end

  fun beginLabel l = boundaryLabel beginPre l
  fun endLabel l = boundaryLabel endPre l

  fun stripCR l =
    let val n = String.size l in
      if n > 0 andalso Char.= (String.sub l (n - 1)) #"\r"
      then String.substring l 0 (n - 1)
      else l
    end

  fun decode input =
    let
      val lines = List.map stripCR (String.fields (fn c => Char.= c #"\n") input)

      fun finishBlock label body =
        case Base64.decode (String.concat (List.rev body)) of
            Some der => (label, der)
          | None => raise Pem ("invalid Base64 body in block " ^ label)

      (* Inside a block: accumulate body lines until the matching END. *)
      fun collect label body ls =
        case ls of
            [] => raise Pem ("BEGIN " ^ label ^ " without matching END")
          | (l :: rest) =>
              (case endLabel l of
                   Some other =>
                     if other = label
                     then finishBlock label body :: scan rest
                     else raise Pem ("END label mismatch: BEGIN " ^ label ^
                                     " vs END " ^ other)
                 | None =>
                     (case beginLabel l of
                          Some _ => raise Pem ("nested BEGIN inside block " ^ label)
                        | None => collect label (l :: body) rest))

      (* Outside any block: skip explanatory text until the next BEGIN. *)
      and scan ls =
        case ls of
            [] => []
          | (l :: rest) =>
              (case beginLabel l of
                   Some label => collect label [] rest
                 | None => scan rest)
    in
      scan lines
    end
end
