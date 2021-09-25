#  [M1: point 1]
#  Explain following in here
#  Name of the module to be created
#  Here, we keep it same as the .c file name.
MODULE	 = proj2

## [M2: point 1]
#  Explain following in here
#  obj-m specifies that after the .c file is compiled to .o object file, KBuild system in kernel will link these files and build a .ko module.
#  ...
obj-m += $(MODULE).o

## [M3: point 1]
#  Explain following in here
#  Only sets the value of KERNELDIR to the build directory if the variable is not already defined.
#  shell uname -r prints out the current shell name and kernel version.
#  ...
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

## [M4: point 1]
#  Gets the present working directory and stores it in variable PWD.
#  ...
PWD := $(shell pwd)

## [M5: point 1]
#  Explain following in here
#  This rule contains all the .c files that need to be built. 
#  In our case, we have only one file that is listed in the variable called MODULE.
#  ...
all: $(MODULE)


## [M6: point 1]
#  Explain following in here
#  This is the main compilation step. 
#  For every .c file encountered in the "all" rule, an object file with .o extension has to be created.
#  $< = first prerequisite file name, usually the source file (.c file in our case)
#  $@ = target file name
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

## [M7: point 1]
#  Explain following in here
#  This command compiles the kernel modules.
#  $(MAKE) is used instead of make in recursive make calls.
#  -C option switches the current directory to the $(KERNELDIR) directory.
#  M option contains the present working directory which stores the path to your kernel module. This info is needed because the make command switches paths.
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

## [M8: point 1]
#  Explain following in here
#  the rule "clean" removes all the compiled files and the kernel module files (Eg, the .o and .ko extensions)
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
