mem <- new.env(parent = emptyenv())

my_cache <- custom_cache(
  get = function(key, missing = NULL) {
    base::get0(key, envir = mem, ifnotfound = missing, inherits = FALSE)
  },

  set = function(key, value) {
    assign(key, value, envir = mem)
    invisible(NULL)
  },

  remove = function(key) {
    if (exists(key, envir = mem, inherits = FALSE)) {
      rm(list = key, envir = mem)
    }
    invisible(NULL)
  },

  # Atomic get-and-delete: preferred for state stores in multi-worker
  # deployments to prevent TOCTOU replay attacks. For per-process caches
  # (like cachem::cache_mem()) this is optional; for shared backends (Redis,
  # database) it should map to the backend's atomic primitive (e.g., GETDEL).
  take = function(key, missing = NULL) {
    val <- base::get0(key, envir = mem, ifnotfound = missing, inherits = FALSE)
    if (exists(key, envir = mem, inherits = FALSE)) {
      rm(list = key, envir = mem)
    }
    val
  },

  info = function() list(max_age = 600)
)
