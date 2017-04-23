####  Makefile for compilation on Linux  ####

OPT=-O3     # Optimization option by default

CC=clang
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
else ifeq "$(ARCH)" "ARM64"
    ARCHITECTURE=_ARM64_
endif

ADDITIONAL_SETTINGS=
ifeq "$(SET)" "EXTENDED"
    ADDITIONAL_SETTINGS=-fwrapv -fomit-frame-pointer -march=native
endif

ifeq "$(GENERIC)" "TRUE"
    USE_GENERIC=-D _GENERIC_
endif

ifeq "$(ARCH)" "ARM"
    ARM_SETTING=-lrt
endif

ifeq "$(ARCH)" "ARM64"
    ARM_SETTING=-lrt
endif

cc=$(COMPILER)
CFLAGS=-c $(OPT) $(ADDITIONAL_SETTINGS) -D $(ARCHITECTURE) -D __LINUX__ $(USE_GENERIC)
LDFLAGS=
ifeq "$(GENERIC)" "TRUE"
    EXTRA_OBJECTS=fp_generic.o
else
ifeq "$(ARCH)" "x64"
    EXTRA_OBJECTS=fp_x64.o fp_x64_gas_asm.o
endif
ifeq "$(ARCH)" "ARM64"
    EXTRA_OBJECTS=fp_arm64.o fp_arm64_asm.o
endif
endif
OBJECTS=kex.o ec_isogeny.o SIDH.o SIDH_setup.o fpx.o $(EXTRA_OBJECTS)
OBJECTS_TEST=test_extras.o
OBJECTS_ARITH_TEST=arith_tests.o $(OBJECTS_TEST) $(OBJECTS)
OBJECTS_KEX_TEST=kex_tests.o $(OBJECTS_TEST) $(OBJECTS)
OBJECTS_ALL=$(OBJECTS) $(OBJECTS_ARITH_TEST) $(OBJECTS_KEX_TEST)

all: arith_test kex_test

kex_test: $(OBJECTS_KEX_TEST)
	$(CC) -o kex_test $(OBJECTS_KEX_TEST) $(ARM_SETTING)

arith_test: $(OBJECTS_ARITH_TEST)
	$(CC) -o arith_test $(OBJECTS_ARITH_TEST) $(ARM_SETTING)

kex.o: kex.c SIDH_internal.h
	$(CC) $(CFLAGS) kex.c

ec_isogeny.o: ec_isogeny.c SIDH_internal.h
	$(CC) $(CFLAGS) ec_isogeny.c

SIDH.o: SIDH.c SIDH_internal.h
	$(CC) $(CFLAGS) SIDH.c

SIDH_setup.o: SIDH_setup.c SIDH_internal.h
	$(CC) $(CFLAGS) SIDH_setup.c

fpx.o: fpx.c SIDH_internal.h
	$(CC) $(CFLAGS) fpx.c

ifeq "$(GENERIC)" "TRUE"
    fp_generic.o: generic/fp_generic.c
	    $(CC) $(CFLAGS) generic/fp_generic.c
else
ifeq "$(ARCH)" "x64"
    fp_x64.o: AMD64/fp_x64.c
	    $(CC) $(CFLAGS) AMD64/fp_x64.c

    fp_x64_gas_asm.o: AMD64/fp_x64_gas_asm.S
	    $(CC) $(CFLAGS) AMD64/fp_x64_gas_asm.S
endif
ifeq "$(ARCH)" "ARM64"
    fp_arm64.o: ARM64/fp_arm64.c
	    $(CC) $(CFLAGS) ARM64/fp_arm64.c

    fp_arm64_asm.o: ARM64/fp_arm64_asm.S
	    $(CC) $(CFLAGS) ARM64/fp_arm64_asm.S
endif
endif

test_extras.o: tests/test_extras.c tests/test_extras.h
	$(CC) $(CFLAGS) tests/test_extras.c

arith_tests.o: tests/arith_tests.c SIDH_internal.h
	$(CC) $(CFLAGS) tests/arith_tests.c

kex_tests.o: tests/kex_tests.c SIDH.h
	$(CC) $(CFLAGS) tests/kex_tests.c

.PHONY: clean

clean:
	rm -f arith_test kex_test fp_generic.o fp_x64.o fp_x64_gas_asm.o fp_arm64.o fp_arm64_asm.o $(OBJECTS_ALL)

