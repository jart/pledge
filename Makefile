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
SOURCE_FILES := cmd/pledge lib/pledge lib/getcpucount lib/sizetol lib/xstrcat
SOURCE_FILES += lib/landlock_create_ruleset lib/unveil lib/ioprio_set
SOURCE_FILES += lib/xjoinpaths lib/copyfd lib/commandv lib/is_linux_2_6_23
SOURCE_FILES += lib/ParsePromises lib/sys_pledge_linux lib/xmalloc lib/xrealloc
SOURCE_FILES += lib/landlock_restrict_self lib/joinpaths
SOURCE_FILES += lib/pthread_block_cancellations lib/pthread_allow_cancellations
SOURCE_FILES += lib/landlock_add_rule lib/xstrdup lib/isabspath lib/endswith
SOURCE_FILES += lib/xdie lib/classifypath

OBJECT_FILES := $(addprefix $(OUTPUT_FOLDER)/obj/, $(addsuffix .o, $(SOURCE_FILES)))

$(OUTPUT_FOLDER)/$(BINARY_NAME): $(OBJECT_FILES)
> $(CC) $(LDFLAGS) -o $@ $(OBJECT_FILES)

$(OUTPUT_FOLDER)/obj/%.o: %.c
> @mkdir --parents $(OUTPUT_FOLDER)/obj/cmd
> @mkdir --parents $(OUTPUT_FOLDER)/obj/lib
> $(CC) -c $< -o $@ $(CFLAGS)

# Include dependencies for the object files
include $(shell [ -d $(OUTPUT_FOLDER)/obj ] && find $(OUTPUT_FOLDER)/obj/ -type f -name '*.d')

# Remove all object, binary and other produced files
clean:
> rm -rf o

