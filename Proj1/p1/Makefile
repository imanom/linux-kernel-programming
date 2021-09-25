## [M1: point 1]
# CUR_DIR = current directory
# shell function communicates with the world outside make files and performs same functions as most shells.
# MAKEFILE_LIST = list of all make files.
# $(lastword $(MAKEFILE_LIST)) = name of current makefile.
# realpath = returns the canonicalized absolute pathname.
# dirname = gets directory name from path.
#  ...
CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

## [M2: point 1]
# Sets CC (the environment variable used to refer to the system's C compiler) to gcc. 
# 
# CFLAGS appends the compiler flags mentioned.
# -O2 specifies optimization level 2, -g specifies compile with debug information
# -Werror specifies that every warning be treated as an error, -Wall gives verbose compiler warnings.
# 
# LDFLAGS specifies linker flags. No linker flag specified here.
#  ...
CC = gcc
CFLAGS += -g 
#-O2 -Werror -Wall
LDFLAGS +=

## [M3: point 1]
#  DEPS_DIR = contains all the dependent files. 
#  ...
DEPS_DIR  := $(CUR_DIR)/.deps$(LIB_SUFFIX)
DEPCFLAGS = -MD -MF $(DEPS_DIR)/$*.d -MP

## [M5: point 1]
#  Returns a list of all the C source files in the directory and stores it in SRC_FILES.
#  ...
SRC_FILES = $(wildcard *.c)

## [M6: point 1]
# Takes all the .c files from SRC_FILES and creates executables with their names (and no extension)
# For example, hello.c will become hello
# EXE_FILES contains all the executables.
#  ...
EXE_FILES = $(SRC_FILES:.c=)

## [M7: point 1]
#  Creates the executables stored in EXE_FILES, and prints out their names.
#  ...
all: $(EXE_FILES)
	echo $(EXE_FILES)

## [M8: point 1]
# ':' symbol is used to define a rule.
# LHS refers to the c file inside the current directory.
# RHS points that the LHS depends on the .c file and the dependent files located in DEPS_DIR.
# The rule then says that to generate the final .c file, make needs to compile using the compiler defined in CC macro.
# -c flag says that we need to generate the object file of the file provided in LHS.
# $< refers to the first item on the dependency list (DEPS_DIR).
# CFLAGS and DEPCFLAGS expand to the macros above.
# ...
%/%.c:%.c $(DEPS_DIR)
	$(CC) $(CFLAGS) $(DEPCFLAGS) -c $@ $<
	

## [M9: point 1]
#  force removes all the executables, whose names are stored in EXE_FILES.
#  ...
clean:
	rm -f $(EXE_FILES)

## [M10: point 1]
#  .PHONY specifies the names that have to executed every time.
# To make the explanation simple, suppose you have a file names "clean", in that case if you run make clean,
# the compiler would assume that it is the file called "clean" and it would consider make clean as up to date.
# To avoid this problem, PHONY specifies those names which always have to be explicitly run.
# In this case - the names all and clean.
#  ...
.PHONY: all clean
