# Resolve a preferred argument and its released spelling without forcing
# a missing argument or changing its default.
resolve_argument_alias <- function(
  value,
  alias,
  value_missing,
  alias_missing,
  name,
  old_name,
  allow_identical = FALSE
) {
  if (alias_missing) {
    return(value)
  }
  if (!value_missing && !(allow_identical && identical(value, alias))) {
    err_input(paste0("Cannot supply both `", name, "` and `", old_name, "`."))
  }
  alias
}

# Alias properties delegate to the stored property, keeping validation and
# updates consistent through either spelling.
api_alias_property <- function(target) {
  force(target)
  S7::new_property(
    getter = function(self) S7::prop(self, target),
    setter = function(self, value) {
      S7::prop(self, target) <- value
      self
    }
  )
}

api_class_constructor <- function(
  class,
  constructor,
  properties = class@properties
) {
  S7::new_class(
    class@name,
    parent = class@parent,
    package = class@package,
    properties = properties,
    constructor = constructor,
    validator = class@validator
  )
}

# Prefer a clearer spelling without moving the released argument or removing
# the released property. The compatibility spelling is appended by name.
api_class_argument_alias <- function(class, old, new) {
  constructor <- class@constructor
  args <- as.list(formals(constructor))
  names(args)[names(args) == old] <- new
  args[old] <- list(NULL)
  formals(constructor) <- as.pairlist(args)
  resolve <- substitute(
    {
      OLD <- resolve_argument_alias(
        NEW,
        OLD,
        missing(NEW),
        missing(OLD),
        NEW_NAME,
        OLD_NAME,
        allow_identical = TRUE
      )
    },
    list(OLD = as.name(old), NEW = as.name(new), NEW_NAME = new, OLD_NAME = old)
  )
  body(constructor) <- as.call(list(as.name("{"), resolve, body(constructor)))
  properties <- class@properties
  properties[[new]] <- api_alias_property(old)
  api_class_constructor(class, constructor, properties)
}

# Preserve the meaning of every positional argument from CRAN 0.5.0.
# Renamed properties also remain readable and writable through their old names.
api_preserve_constructor <- function(class, released, aliases) {
  constructor <- class@constructor
  args <- as.list(formals(constructor))
  preferred <- released
  renamed <- released %in% names(aliases)
  preferred[renamed] <- unname(aliases[released[renamed]])
  stopifnot(all(preferred %in% names(args)))
  args <- args[c(preferred, setdiff(names(args), preferred))]
  properties <- class@properties
  resolutions <- list()
  for (old in names(aliases)) {
    new <- aliases[[old]]
    if (!old %in% names(args)) {
      args[old] <- list(NULL)
      resolutions[[old]] <- substitute(
        {
          NEW <- resolve_argument_alias(
            NEW,
            OLD,
            missing(NEW),
            missing(OLD),
            NEW_NAME,
            OLD_NAME,
            allow_identical = TRUE
          )
        },
        list(
          OLD = as.name(old),
          NEW = as.name(new),
          NEW_NAME = new,
          OLD_NAME = old
        )
      )
    }
    if (!old %in% names(properties)) {
      properties[[old]] <- api_alias_property(new)
    }
  }
  formals(constructor) <- as.pairlist(args)
  body(constructor) <- as.call(c(
    list(as.name("{")),
    unname(resolutions),
    list(body(constructor))
  ))
  api_class_constructor(class, constructor, properties)
}
