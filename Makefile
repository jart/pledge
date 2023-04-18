# Makefiles are prettier like this
ifeq ($(origin .RECIPEPREFIX), undefined)
  $(error This Make does not support .RECIPEPREFIX. \
        Please use GNU Make 3.82 or later)
endif
.RECIPEPREFIX = >

# Use bash as the shell
SHELL := bash

# ...And use strict flags with it to make sure things fail if a step in there
# fails
.SHELLFLAGS := -eu -o pipefail -c

# Delete the target file of a Make rule if it fails - this guards against
# broken files
.DELETE_ON_ERROR:

# --no-builtin-rules: I'd rather make my own rules myself, make, thanks :)
MAKEFLAGS += --no-builtin-rules

# We use `override` to enable setting part of CFLAGS on the command line

# This makes the compiler generate dependency files, which will solve any
# header-related dependency problems we could have had
override CFLAGS += -MMD -MP -MF $@.d

# Make it simpler to include library include files
override CFLAGS += -I.

# We need functions provided by defining _GNU_SOURCE
override CFLAGS += -D_GNU_SOURCE

# We need to compile as PIC code since we're making shared libraries here
override CFLAGS += -fPIC

# LDFLAGS should contain CFLAGS (seperate so command-line can add to it, and
# to correspond to usual practice)
override LDFLAGS += $(CFLAGS)

OUTPUT_FOLDER = o/$(MODE)

.PHONY: all clean

all: $(OUTPUT_FOLDER)/pledge $(OUTPUT_FOLDER)/sandbox.so

# Note: we cannot merge the source file list for pledge and the sandbox as this may otherwise result in constructors calling forbidden syscalls in the sandbox
PLEDGE_SOURCE_FILES := cmd/pledge
PLEDGE_SOURCE_FILES += libc/calls/commandv libc/calls/getcpucount libc/calls/islinux
PLEDGE_SOURCE_FILES += libc/calls/landlock_add_rule libc/calls/landlock_create_ruleset
PLEDGE_SOURCE_FILES += libc/calls/landlock_restrict_self libc/calls/parsepromises
PLEDGE_SOURCE_FILES += libc/calls/pledge libc/calls/pledge-linux libc/calls/unveil

PLEDGE_SOURCE_FILES += libc/x/xdie libc/x/xjoinpaths libc/x/xmalloc libc/x/xrealloc
PLEDGE_SOURCE_FILES += libc/x/xstrcat libc/x/xstrdup

PLEDGE_SOURCE_FILES += libc/elf/checkelfaddress libc/elf/getelfsegmentheaderaddress

PLEDGE_SOURCE_FILES += libc/str/classifypath libc/str/endswith libc/str/isabspath

PLEDGE_SOURCE_FILES += libc/intrin/promises libc/intrin/pthread_setcancelstate

PLEDGE_SOURCE_FILES += libc/fmt/joinpaths libc/fmt/sizetol

PLEDGE_SOURCE_FILES += libc/runtime/isdynamicexecutable

PLEDGE_SOURCE_FILES += libc/sysv/calls/ioprio_set

SANDBOX_SOURCE_FILES := cmd/sandbox
SANDBOX_SOURCE_FILES += libc/calls/pledge-linux


SANDBOX_OBJECT_FILES := $(addprefix $(OUTPUT_FOLDER)/, $(addsuffix .o, $(SANDBOX_SOURCE_FILES)))
PLEDGE_OBJECT_FILES := $(addprefix $(OUTPUT_FOLDER)/, $(addsuffix .o, $(PLEDGE_SOURCE_FILES)))

# First we need to have a shared object for the sandbox
$(OUTPUT_FOLDER)/sandbox.so: $(SANDBOX_OBJECT_FILES)
> $(CC) $(LDFLAGS) -shared -o $@ $^

# Next we need to make an object file out of that shared object containing the shared object as a symbol
$(OUTPUT_FOLDER)/embedded-sandbox.o: $(OUTPUT_FOLDER)/sandbox.so
> ld -r -b binary -o $@ $^

# Finally we need to embed the sandbox into our executable so it can copy it out when needed
$(OUTPUT_FOLDER)/pledge: $(PLEDGE_OBJECT_FILES) $(OUTPUT_FOLDER)/embedded-sandbox.o
> $(CC) $(LDFLAGS) -o $@ $^

$(OUTPUT_FOLDER)/%.o: %.c
> @mkdir --parents $(OUTPUT_FOLDER)/cmd
> @mkdir --parents $(OUTPUT_FOLDER)/libc/calls
> @mkdir --parents $(OUTPUT_FOLDER)/libc/sysv/calls
> @mkdir --parents $(OUTPUT_FOLDER)/libc/str
> @mkdir --parents $(OUTPUT_FOLDER)/libc/mem
> @mkdir --parents $(OUTPUT_FOLDER)/libc/fmt
> @mkdir --parents $(OUTPUT_FOLDER)/libc/intrin
> @mkdir --parents $(OUTPUT_FOLDER)/libc/x
> @mkdir --parents $(OUTPUT_FOLDER)/libc/runtime
> @mkdir --parents $(OUTPUT_FOLDER)/libc/elf
> $(CC) -c $< -o $@ $(CFLAGS)

# Include dependencies for the object files
include $(shell [ -d $(OUTPUT_FOLDER)/obj ] && find $(OUTPUT_FOLDER)/ -type f -name '*.d')

# Remove all object, binary and other produced files
clean:
> rm -rf ./o/

