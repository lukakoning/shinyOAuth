state_test_wrap <- function(wrapper) {
  base64url_encode(charToRaw(jsonlite::toJSON(wrapper, auto_unbox = TRUE)))
}

state_test_unwrap <- function(token) {
  jsonlite::fromJSON(rawToChar(base64url_decode_raw(token)))
}

state_test_gcm_fixture <- function() {
  # Python cryptography AESGCM, independent of R's openssl bindings.
  hex <- function(x) as.raw(strtoi(substring(
    x, seq.int(1L, nchar(x), 2L), seq.int(2L, nchar(x), 2L)
  ), 16L))
  list(
    key = as.raw(0:31),
    plaintext = charToRaw('{"state":"valid","issued_at":1}'),
    wrapper = list(
      v = 2L,
      iv = base64url_encode(as.raw(0:11)),
      ct = base64url_encode(hex(
        "3c20a56fa491a739b763e1eadd801c4faff4ee47830e3a18670691a727587d"
      )),
      tg = base64url_encode(hex("47bb33ec2529b25d01ad4faa1753138e"))
    )
  )
}

state_test_flip_byte <- function(bytes, position = 1L, bit = 0L) {
  bytes[[position]] <- as.raw(bitwXor(
    as.integer(bytes[[position]]), bitwShiftL(1L, bit)
  ))
  bytes
}
