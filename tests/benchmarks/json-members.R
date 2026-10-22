# Run from the repository root with Rscript tests/benchmarks/json-members.R.
pkgload::load_all(quiet = TRUE)
for (unicode in c(FALSE, TRUE)) {
  for (n in c(1000L, 2000L, 4000L, 8000L)) {
    json <- paste0(
      '{"prefix":"',
      if (unicode) "\u00e9" else "x",
      '",',
      paste0('"k', seq_len(n), '":0', collapse = ","),
      '}'
    )
    elapsed <- replicate(
      3L,
      system.time(
        shinyOAuth:::reject_duplicate_json_object_members(json, "JSON")
      )[["elapsed"]]
    )
    print(c(
      unicode = unicode,
      members = n,
      bytes = nchar(json, type = "bytes"),
      elapsed = median(elapsed)
    ))
  }
}
