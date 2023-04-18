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

# --warn-undefined-variables: Referencing undefined variables is probably
# wrong...
# --no-builtin-rules: I'd rather make my own rules myself, make, thanks :)
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

# We use `override` to enable setting part of CFLAGS on the command line

# This makes the compiler generate dependency files, which will solve any
# header-related dependency problems we could have had
override CFLAGS += -MMD -MP -MF $@.d

# Make it simpler to include library include files
override CFLAGS += -I.

# We need functions provided by defining _GNU_SOURCE
override CFLAGS += -D_GNU_SOURCE

# LDFLAGS should contain CFLAGS (seperate so command-line can add to it, and
# to correspond to usual practice)
override LDFLAGS += $(CFLAGS)

OUTPUT_FOLDER = o/

.PHONY: all clean

.PREVIOUS: $(OUTPUT_FOLDER)/obj/%.o

BINARY_NAME := pledge

all: $(OUTPUT_FOLDER)/$(BINARY_NAME)

# Program source files
SOURCE_FILES := cmd/pledge

SOURCE_FILES += libc/calls/commandv libc/calls/getcpucount libc/calls/islinux
SOURCE_FILES += libc/calls/landlock_add_rule libc/calls/landlock_create_ruleset
SOURCE_FILES += libc/calls/landlock_restrict_self libc/calls/parsepromises
SOURCE_FILES += libc/calls/pledge libc/calls/pledge-linux libc/calls/unveil

SOURCE_FILES += libc/x/xdie libc/x/xjoinpaths libc/x/xmalloc libc/x/xrealloc
SOURCE_FILES += libc/x/xstrcat libc/x/xstrdup

SOURCE_FILES += libc/str/classifypath libc/str/endswith libc/str/isabspath 

SOURCE_FILES += libc/fmt/joinpaths libc/fmt/sizetol

SOURCE_FILES += libc/sysv/calls/ioprio_set

SOURCE_FILES += libc/intrin/promises libc/intrin/pthread_setcancelstate

SOURCE_FILES += libc/mem/copyfd

OBJECT_FILES := $(addprefix $(OUTPUT_FOLDER)/obj/, $(addsuffix .o, $(SOURCE_FILES)))

$(OUTPUT_FOLDER)/$(BINARY_NAME): $(OBJECT_FILES)
> $(CC) $(LDFLAGS) -o $@ $(OBJECT_FILES)

$(OUTPUT_FOLDER)/obj/%.o: %.c
> @mkdir --parents $(OUTPUT_FOLDER)/obj/cmd
> @mkdir --parents $(OUTPUT_FOLDER)/obj/libc/calls
> @mkdir --parents $(OUTPUT_FOLDER)/obj/libc/sysv/calls
> @mkdir --parents $(OUTPUT_FOLDER)/obj/libc/str
> @mkdir --parents $(OUTPUT_FOLDER)/obj/libc/mem
> @mkdir --parents $(OUTPUT_FOLDER)/obj/libc/fmt
> @mkdir --parents $(OUTPUT_FOLDER)/obj/libc/intrin
> @mkdir --parents $(OUTPUT_FOLDER)/obj/libc/x
> $(CC) -c $< -o $@ $(CFLAGS)

# Include dependencies for the object files
include $(shell [ -d $(OUTPUT_FOLDER)/obj ] && find $(OUTPUT_FOLDER)/obj/ -type f -name '*.d')

# Remove all object, binary and other produced files
clean:
> rm -rf ./o/

