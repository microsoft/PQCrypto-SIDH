####  Makefile for compilation on Linux  ####

OPT=-O3     # Optimization option by default

CC=clang
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCHITECTURE=_AMD64_
USE_OPT_LEVEL=_FAST_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
    USE_OPT_LEVEL=_FAST_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
    USE_OPT_LEVEL=_GENERIC_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    USE_OPT_LEVEL=_GENERIC_
    ARM_TARGET=YES
else ifeq "$(ARCH)" "ARM64"
    ARCHITECTURE=_ARM64_
    USE_OPT_LEVEL=_FAST_
    ARM_TARGET=YES
endif

ifeq "$(OPT_LEVEL)" "GENERIC"
    USE_OPT_LEVEL=_GENERIC_
endif

ifeq "$(ARM_TARGET)" "YES"
    ARM_SETTING=-lrt
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
    ifeq "$(USE_OPT_LEVEL)" "_FAST_"
        MULX=-D _MULX_
        ifeq "$(USE_MULX)" "FALSE"
            MULX=
        else
            ADX=-D _ADX_
            ifeq "$(USE_ADX)" "FALSE"
                ADX=
            endif
        endif
    endif
endif

AR=ar rcs
RANLIB=ranlib

ADDITIONAL_SETTINGS=-march=native
ifeq "$(CC)" "clang"
ifeq "$(ARM_TARGET)" "YES"
    ADDITIONAL_SETTINGS=
endif
endif

CFLAGS=$(OPT) $(ADDITIONAL_SETTINGS) -D $(ARCHITECTURE) -D __LINUX__ -D $(USE_OPT_LEVEL) $(MULX) $(ADX)
LDFLAGS=-lm
ifeq "$(USE_OPT_LEVEL)" "_GENERIC_"
    EXTRA_OBJECTS_434=objs434/fp_generic.o
    EXTRA_OBJECTS_503=objs503/fp_generic.o
    EXTRA_OBJECTS_610=objs610/fp_generic.o
    EXTRA_OBJECTS_751=objs751/fp_generic.o
else ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(ARCHITECTURE)" "_AMD64_"
    EXTRA_OBJECTS_434=objs434/fp_x64.o objs434/fp_x64_asm.o
    EXTRA_OBJECTS_503=objs503/fp_x64.o objs503/fp_x64_asm.o
    EXTRA_OBJECTS_610=objs610/fp_x64.o objs610/fp_x64_asm.o
    EXTRA_OBJECTS_751=objs751/fp_x64.o objs751/fp_x64_asm.o
else ifeq "$(ARCHITECTURE)" "_ARM64_"
    EXTRA_OBJECTS_434=objs434/fp_generic.o
    EXTRA_OBJECTS_503=objs503/fp_arm64.o objs503/fp_arm64_asm.o
    EXTRA_OBJECTS_610=objs610/fp_generic.o
    EXTRA_OBJECTS_751=objs751/fp_arm64.o objs751/fp_arm64_asm.o
endif
endif
OBJECTS_434=objs434/P434.o $(EXTRA_OBJECTS_434) objs/random.o objs/fips202.o
OBJECTS_503=objs503/P503.o $(EXTRA_OBJECTS_503) objs/random.o objs/fips202.o
OBJECTS_610=objs610/P610.o $(EXTRA_OBJECTS_610) objs/random.o objs/fips202.o
OBJECTS_751=objs751/P751.o $(EXTRA_OBJECTS_751) objs/random.o objs/fips202.o

all: lib434 lib503 lib610 lib751 tests KATS

objs434/%.o: src/P434/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

objs503/%.o: src/P503/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

objs610/%.o: src/P610/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

objs751/%.o: src/P751/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

ifeq "$(USE_OPT_LEVEL)" "_GENERIC_"		
    objs434/fp_generic.o: src/P434/generic/fp_generic.c
	    $(CC) -c $(CFLAGS) src/P434/generic/fp_generic.c -o objs434/fp_generic.o

    objs503/fp_generic.o: src/P503/generic/fp_generic.c
	    $(CC) -c $(CFLAGS) src/P503/generic/fp_generic.c -o objs503/fp_generic.o

    objs610/fp_generic.o: src/P610/generic/fp_generic.c
	    $(CC) -c $(CFLAGS) src/P610/generic/fp_generic.c -o objs610/fp_generic.o

    objs751/fp_generic.o: src/P751/generic/fp_generic.c
	    $(CC) -c $(CFLAGS) src/P751/generic/fp_generic.c -o objs751/fp_generic.o
else ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(ARCHITECTURE)" "_AMD64_"		
    objs434/fp_x64.o: src/P434/AMD64/fp_x64.c
	    $(CC) -c $(CFLAGS) src/P434/AMD64/fp_x64.c -o objs434/fp_x64.o

    objs434/fp_x64_asm.o: src/P434/AMD64/fp_x64_asm.S
	    $(CC) -c $(CFLAGS) src/P434/AMD64/fp_x64_asm.S -o objs434/fp_x64_asm.o

    objs503/fp_x64.o: src/P503/AMD64/fp_x64.c
	    $(CC) -c $(CFLAGS) src/P503/AMD64/fp_x64.c -o objs503/fp_x64.o

    objs503/fp_x64_asm.o: src/P503/AMD64/fp_x64_asm.S
	    $(CC) -c $(CFLAGS) src/P503/AMD64/fp_x64_asm.S -o objs503/fp_x64_asm.o

    objs610/fp_x64.o: src/P610/AMD64/fp_x64.c
	    $(CC) -c $(CFLAGS) src/P610/AMD64/fp_x64.c -o objs610/fp_x64.o

    objs610/fp_x64_asm.o: src/P610/AMD64/fp_x64_asm.S
	    $(CC) -c $(CFLAGS) src/P610/AMD64/fp_x64_asm.S -o objs610/fp_x64_asm.o

    objs751/fp_x64.o: src/P751/AMD64/fp_x64.c
	    $(CC) -c $(CFLAGS) src/P751/AMD64/fp_x64.c -o objs751/fp_x64.o

    objs751/fp_x64_asm.o: src/P751/AMD64/fp_x64_asm.S
	    $(CC) -c $(CFLAGS) src/P751/AMD64/fp_x64_asm.S -o objs751/fp_x64_asm.o
else ifeq "$(ARCHITECTURE)" "_ARM64_"		
    objs434/fp_generic.o: src/P434/generic/fp_generic.c
	    $(CC) -c $(CFLAGS) src/P434/generic/fp_generic.c -o objs434/fp_generic.o

    objs503/fp_arm64.o: src/P503/ARM64/fp_arm64.c
	    $(CC) -c $(CFLAGS) src/P503/ARM64/fp_arm64.c -o objs503/fp_arm64.o

    objs503/fp_arm64_asm.o: src/P503/ARM64/fp_arm64_asm.S
	    $(CC) -c $(CFLAGS) src/P503/ARM64/fp_arm64_asm.S -o objs503/fp_arm64_asm.o

    objs610/fp_generic.o: src/P610/generic/fp_generic.c
	    $(CC) -c $(CFLAGS) src/P610/generic/fp_generic.c -o objs610/fp_generic.o

    objs751/fp_arm64.o: src/P751/ARM64/fp_arm64.c
	    $(CC) -c $(CFLAGS) src/P751/ARM64/fp_arm64.c -o objs751/fp_arm64.o

    objs751/fp_arm64_asm.o: src/P751/ARM64/fp_arm64_asm.S
	    $(CC) -c $(CFLAGS) src/P751/ARM64/fp_arm64_asm.S -o objs751/fp_arm64_asm.o
endif
endif

objs/random.o: src/random/random.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) src/random/random.c -o objs/random.o

objs/fips202.o: src/sha3/fips202.c
	$(CC) -c $(CFLAGS) src/sha3/fips202.c -o objs/fips202.o

lib434: $(OBJECTS_434)
	rm -rf lib434 sike434 sidh434
	mkdir lib434 sike434 sidh434
	$(AR) lib434/libsidh.a $^
	$(RANLIB) lib434/libsidh.a

lib503: $(OBJECTS_503)
	rm -rf lib503 sike503 sidh503
	mkdir lib503 sike503 sidh503
	$(AR) lib503/libsidh.a $^
	$(RANLIB) lib503/libsidh.a

lib610: $(OBJECTS_610)
	rm -rf lib610 sike610 sidh610
	mkdir lib610 sike610 sidh610
	$(AR) lib610/libsidh.a $^
	$(RANLIB) lib610/libsidh.a

lib751: $(OBJECTS_751)
	rm -rf lib751 sike751 sidh751
	mkdir lib751 sike751 sidh751
	$(AR) lib751/libsidh.a $^
	$(RANLIB) lib751/libsidh.a

tests: lib434 lib503 lib610 lib751
	$(CC) $(CFLAGS) -L./lib434 tests/arith_tests-p434.c tests/test_extras.c -lsidh $(LDFLAGS) -o arith_tests-p434 $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib503 tests/arith_tests-p503.c tests/test_extras.c -lsidh $(LDFLAGS) -o arith_tests-p503 $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib610 tests/arith_tests-p610.c tests/test_extras.c -lsidh $(LDFLAGS) -o arith_tests-p610 $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib751 tests/arith_tests-p751.c tests/test_extras.c -lsidh $(LDFLAGS) -o arith_tests-p751 $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib434 tests/test_SIDHp434.c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh434/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib503 tests/test_SIDHp503.c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh503/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib610 tests/test_SIDHp610.c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh610/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib751 tests/test_SIDHp751.c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh751/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib434 tests/test_SIKEp434.c tests/test_extras.c -lsidh $(LDFLAGS) -o sike434/test_SIKE $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib503 tests/test_SIKEp503.c tests/test_extras.c -lsidh $(LDFLAGS) -o sike503/test_SIKE $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib610 tests/test_SIKEp610.c tests/test_extras.c -lsidh $(LDFLAGS) -o sike610/test_SIKE $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib751 tests/test_SIKEp751.c tests/test_extras.c -lsidh $(LDFLAGS) -o sike751/test_SIKE $(ARM_SETTING)

# AES
AES_OBJS=objs/aes.o objs/aes_c.o

objs/%.o: tests/aes/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

lib434_for_KATs: $(OBJECTS_434) $(AES_OBJS)
	$(AR) lib434/libsidh_for_testing.a $^
	$(RANLIB) lib434/libsidh_for_testing.a

lib503_for_KATs: $(OBJECTS_503) $(AES_OBJS)
	$(AR) lib503/libsidh_for_testing.a $^
	$(RANLIB) lib503/libsidh_for_testing.a

lib610_for_KATs: $(OBJECTS_610) $(AES_OBJS)
	$(AR) lib610/libsidh_for_testing.a $^
	$(RANLIB) lib610/libsidh_for_testing.a

lib751_for_KATs: $(OBJECTS_751) $(AES_OBJS)
	$(AR) lib751/libsidh_for_testing.a $^
	$(RANLIB) lib751/libsidh_for_testing.a

KATS: lib434_for_KATs lib503_for_KATs lib610_for_KATs lib751_for_KATs
	$(CC) $(CFLAGS) -L./lib434 tests/PQCtestKAT_kem434.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike434/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib503 tests/PQCtestKAT_kem503.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike503/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib610 tests/PQCtestKAT_kem610.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike610/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib751 tests/PQCtestKAT_kem751.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike751/PQCtestKAT_kem $(ARM_SETTING)

check: tests

.PHONY: clean

clean:
	rm -rf *.req objs434 objs503 objs610 objs751 objs lib434 lib503 lib610 lib751 sidh434 sidh503 sidh610 sidh751 sike434 sike503 sike610 sike751 arith_tests-*

