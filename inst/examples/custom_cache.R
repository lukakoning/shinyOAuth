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
      return(TRUE) # signal successful deletion
    }
    return(FALSE) # key did not exist
  },

  info = function() list(max_age = 600)
)

# Can be used as state_store:
# oauth_client(..., state_store = my_cache)

# Or as JWKS cache:
# oauth_provider(..., jwks_cache = my_cache)
