# NA

This document contains documentation about using S7; taken from the S7
vignettes.

------------------------------------------------------------------------

- Source: <https://github.com/RConsortium/S7>

- MIT license: Copyright (c) 2021 S7 authors

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
“Software”), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

------------------------------------------------------------------------

## \# Basic usage of S7 (taken from the S7 package vignettes)

title: “S7 basics” output: rmarkdown::html_vignette vignette: \> % % % —

`{r, include = FALSE} knitr::opts_chunk$set( collapse = TRUE, comment = "#>" )`

The S7 package provides a new OOP system designed to be a successor to
S3 and S4. It has been designed and implemented collaboratively by the
RConsortium Object-Oriented Programming Working Group, which includes
representatives from R-Core, BioConductor, RStudio/tidyverse, and the
wider R community.

This vignette gives an overview of the most important parts of S7:
classes and objects, generics and methods, and the basics of method
dispatch and inheritance.

`{r setup} library(S7)`

## Classes and objects

S7 classes have a formal definition that you create with `new_class()`.
There are two arguments that you’ll use with almost every class:

- The `name` of the class, supplied in the first argument.
- The class `properties`, the data associated with each instance of the
  class. The easiest way to define properties is to supply a named list
  where the values define the valid types of the property.

The following code defines a simple `dog` class with two properties: a
character `name` and a numeric `age`.

`{r} Dog <- new_class("Dog", properties = list( name = class_character, age = class_numeric )) Dog`

S7 provides a number of built-in definitions that allow you to refer to
existing base types that are not S7 classes. You can recognize these
definitions because they all start with `class_`.

Note that I’ve assigned the return value of `new_class()` to an object
with the same name as the class. This is important! That object
represents the class and is what you use to construct instances of the
class:

`{r} lola <- Dog(name = "Lola", age = 11) lola`

Once you have an S7 object, you can get and set properties using `@`:

`{r} lola@age <- 12 lola@age`

S7 automatically validates the type of the property using the type
supplied in `new_class()`:

`{r, error = TRUE} lola@age <- "twelve"`

Given an object, you can retrieve its class `S7_class()`:

`{r} S7_class(lola)`

S7 objects also have an S3
[`class()`](https://rdrr.io/r/base/class.html). This is used for
compatibility with existing S3 generics and you can learn more about it
in `vignette("compatibility")`.

`{r} class(lola)`

If you want to learn more about the details of S7 classes and objects,
including validation methods and more details of properties, please see
`vignette("classes-objects")`.

## Generics and methods

S7, like S3 and S4, is built around the idea of **generic functions,**
or **generics** for short. A generic defines an interface, which uses a
different implementation depending on the class of one or more
arguments. The implementation for a specific class is called a
**method**, and the generic finds that appropriate method by performing
**method dispatch**.

Use `new_generic()` to create a S7 generic. In its simplest form, it
only needs two arguments: the name of the generic (used in error
messages) and the name of the argument used for method dispatch:

`{r} speak <- new_generic("speak", "x")`

Like with `new_class()`, you should always assign the result of
`new_generic()` to a variable with the same name as the first argument.

Once you have a generic, you can register methods for specific classes
with `method(generic, class) <- implementation`.

`{r} method(speak, Dog) <- function(x) { "Woof" }`

Once the method is registered, the generic will use it when appropriate:

`{r} speak(lola)`

Let’s define another class, this one for cats, and define another method
for `speak()`:

\`\`\`{r} Cat \<- new_class(“Cat”, properties = list( name =
class_character, age = class_double )) method(speak, Cat) \<-
function(x) { “Meow” }

fluffy \<- Cat(name = “Fluffy”, age = 5) speak(fluffy)

    You get an error if you call the generic with a class that doesn't have a method:

    ```{r, error = TRUE}
    speak(1)

## Method dispatch and inheritance

The `cat` and `dog` classes share the same properties, so we could use a
common parent class to extract out the duplicated specification. We
first define the parent class:

`{r} Pet <- new_class("Pet", properties = list( name = class_character, age = class_numeric ) )`

Then use the `parent` argument to `new_class:`

\`\`\`{r} Cat \<- new_class(“Cat”, parent = Pet) Dog \<-
new_class(“Dog”, parent = Pet)

Cat Dog

    Because we have created new classes, we need to recreate the existing `lola` and `fluffy` objects:

    ```{r}
    lola <- Dog(name = "Lola", age = 11)
    fluffy <- Cat(name = "Fluffy", age = 5)

Method dispatch takes advantage of the hierarchy of parent classes: if a
method is not defined for a class, it will try the method for the parent
class, and so on until it finds a method or gives up with an error. This
inheritance is a powerful mechanism for sharing code across classes.

\`\`\`{r} describe \<- new_generic(“describe”, “x”) method(describe,
Pet) \<- function(x) { paste0(<x@name>, ” is “, <x@age>,” years old”) }
describe(lola) describe(fluffy)

method(describe, Dog) \<- function(x) { paste0(<x@name>, ” is a “,
<x@age>,” year old dog”) } describe(lola) describe(fluffy)

    You can define a fallback method for any S7 object by registering a method for `S7_object`:

    ```{r}
    method(describe, S7_object) <- function(x) {
      "An S7 object"
    }

    Cocktail <- new_class("Cocktail",
      properties = list(
        ingredients = class_character
      )
    )
    martini <- Cocktail(ingredients = c("gin", "vermouth"))
    describe(martini)

Printing a generic will show you which methods are currently defined:

`{r} describe`

And you can use `method()` to retrieve the implementation of one of
those methods:

`{r} method(describe, Pet)`

## \# Using S7 in a package (taken from the S7 package vignettes)

title: “Using S7 in a package” output: rmarkdown::html_vignette
vignette: \> % % % —

`{r, include = FALSE} knitr::opts_chunk$set( collapse = TRUE, comment = "#>" )`

This vignette outlines the most important things you need to know about
using S7 in a package. S7 is new, so few people have used it in a
package yet; this means that this vignette is likely incomplete, and
we’d love your help to make it better. Please [let us
know](https://github.com/RConsortium/S7/issues/new) if you have
questions that this vignette doesn’t answer.

`{r setup} library(S7)`

## Method registration

You should always call `methods_register()` in your `.onLoad()`:

`{r} .onLoad <- function(...) { S7::methods_register() }`

This is S7’s way of registering methods, rather than using export
directives in your `NAMESPACE` like S3 and S4 do. This is only strictly
necessary if registering methods for generics in other packages, but
there’s no harm in adding it and it ensures that you won’t forget later.
(And if you’re not importing S7 into your namespace it will quiet an
`R CMD check` `NOTE`.`)`

## Documentation and exports

If you want users to create instances of your class, you will need to
export the class constructor. That means you will also need to document
it, and since the constructor is a function, that means you have to
document the arguments which will be the properties of the class (unless
you have customised the constructor).

If you export a class, you must also set the `package` argument,
ensuring that classes with the same name are disambiguated across
packages.

You should document generics like regular functions (since they are!).
If you expect others to create their own methods for your generic, you
may want to include an section describing the properties that you expect
all methods to have. We plan to provide an easy way to document all
methods for a generic, but have not yet implemented it. You can track
progress at <https://github.com/RConsortium/S7/issues/167>.

We don’t currently have any recommendations on documenting methods.
There’s no need to document them in order to pass `R CMD check`, but
obviously there are cases where it’s nice to provide additional details
for a method, particularly if it takes extra arguments compared to the
generic. We’re tracking that issue at
<https://github.com/RConsortium/S7/issues/315>.

## Backward compatibility

If you are using S7 in a package *and* you want your package to work in
versions of R before 4.3.0, you need to know that in these versions of R
`@` only works with S4 objects. There are two workarounds. The easiest
and least convenient workaround is to just `prop()` instead of `@`.
Otherwise, you can conditionally make an S7-aware `@` available to your
package with this custom `NAMESPACE` directive:

``` r
# enable usage of <S7_object>@name in package code
#' @rawNamespace if (getRversion() < "4.3.0") importFrom("S7", "@")
NULL
```

`@` will work for users of your package because S7 automatically
attaches an environment containing the needed definition when it’s
loaded.
