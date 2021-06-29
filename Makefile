####  Makefile for compilation on Unix-like operative systems  ####

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
else ifeq "$(ARCH)" "s390x"
    ARCHITECTURE=_S390X_
    USE_OPT_LEVEL=_GENERIC_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    USE_OPT_LEVEL=_GENERIC_
    ARM_TARGET=YES
else ifeq "$(ARCH)" "ARM64"
    ARCHITECTURE=_ARM64_
    USE_OPT_LEVEL=_FAST_
    ARM_TARGET=YES
else ifeq "$(ARCH)" "PPC64LE"
    ARCHITECTURE=_PPC64LE_
    USE_OPT_LEVEL=_GENERIC_
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
ifeq "$(ARCHITECTURE)" "_S390X_"
	ADDITIONAL_SETTINGS=-march=z10
endif
ifeq "$(ARCHITECTURE)" "_PPC64LE_"
	ADDITIONAL_SETTINGS=
endif

VALGRIND_CFLAGS=
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
VALGRIND_CFLAGS= -g -O0 -DDO_VALGRIND_CHECK
endif

ifeq "$(EXTRA_CFLAGS)" ""
CFLAGS= -O3     # Optimization option by default
else
CFLAGS= $(EXTRA_CFLAGS)
endif
CFLAGS+= $(VALGRIND_CFLAGS)
CFLAGS+= -std=gnu11 -Wall $(ADDITIONAL_SETTINGS) -D $(ARCHITECTURE) -D __NIX__ -D $(USE_OPT_LEVEL) $(MULX) $(ADX)
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
    EXTRA_OBJECTS_434=objs434/fp_arm64.o objs434/fp_arm64_asm.o
    EXTRA_OBJECTS_503=objs503/fp_arm64.o objs503/fp_arm64_asm.o
    EXTRA_OBJECTS_610=objs610/fp_arm64.o objs610/fp_arm64_asm.o
    EXTRA_OBJECTS_751=objs751/fp_arm64.o objs751/fp_arm64_asm.o
endif
endif
OBJECTS_434=objs434/P434.o $(EXTRA_OBJECTS_434) objs/random.o objs/fips202.o
OBJECTS_503=objs503/P503.o $(EXTRA_OBJECTS_503) objs/random.o objs/fips202.o
OBJECTS_610=objs610/P610.o $(EXTRA_OBJECTS_610) objs/random.o objs/fips202.o
OBJECTS_751=objs751/P751.o $(EXTRA_OBJECTS_751) objs/random.o objs/fips202.o
OBJECTS_434_COMP=objs434comp/P434_compressed.o $(EXTRA_OBJECTS_434) objs/random.o objs/fips202.o
OBJECTS_503_COMP=objs503comp/P503_compressed.o $(EXTRA_OBJECTS_503) objs/random.o objs/fips202.o
OBJECTS_610_COMP=objs610comp/P610_compressed.o $(EXTRA_OBJECTS_610) objs/random.o objs/fips202.o
OBJECTS_751_COMP=objs751comp/P751_compressed.o $(EXTRA_OBJECTS_751) objs/random.o objs/fips202.o

all: lib434 lib503 lib610 lib751 lib434comp lib503comp lib610comp lib751comp tests KATS

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

objs434comp/%.o: src/P434/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

objs503comp/%.o: src/P503/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

objs610comp/%.o: src/P610/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

objs751comp/%.o: src/P751/%.c
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
    objs434/fp_arm64.o: src/P434/ARM64/fp_arm64.c
	    $(CC) -c $(CFLAGS) src/P434/ARM64/fp_arm64.c -o objs434/fp_arm64.o

    objs434/fp_arm64_asm.o: src/P434/ARM64/fp_arm64_asm.S
	    $(CC) -c $(CFLAGS) src/P434/ARM64/fp_arm64_asm.S -o objs434/fp_arm64_asm.o

    objs503/fp_arm64.o: src/P503/ARM64/fp_arm64.c
	    $(CC) -c $(CFLAGS) src/P503/ARM64/fp_arm64.c -o objs503/fp_arm64.o

    objs503/fp_arm64_asm.o: src/P503/ARM64/fp_arm64_asm.S
	    $(CC) -c $(CFLAGS) src/P503/ARM64/fp_arm64_asm.S -o objs503/fp_arm64_asm.o

    objs610/fp_arm64.o: src/P610/ARM64/fp_arm64.c
	    $(CC) -c $(CFLAGS) src/P610/ARM64/fp_arm64.c -o objs610/fp_arm64.o

    objs610/fp_arm64_asm.o: src/P610/ARM64/fp_arm64_asm.S
	    $(CC) -c $(CFLAGS) src/P610/ARM64/fp_arm64_asm.S -o objs610/fp_arm64_asm.o

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

lib434comp: $(OBJECTS_434_COMP)
	rm -rf lib434comp sike434_compressed sidh434_compressed
	mkdir lib434comp sike434_compressed sidh434_compressed
	$(AR) lib434comp/libsidh.a $^
	$(RANLIB) lib434comp/libsidh.a

lib503comp: $(OBJECTS_503_COMP)
	rm -rf lib503comp sike503_compressed sidh503_compressed
	mkdir lib503comp sike503_compressed sidh503_compressed
	$(AR) lib503comp/libsidh.a $^
	$(RANLIB) lib503comp/libsidh.a

lib610comp: $(OBJECTS_610_COMP)
	rm -rf lib610comp sike610_compressed sidh610_compressed
	mkdir lib610comp sike610_compressed sidh610_compressed
	$(AR) lib610comp/libsidh.a $^
	$(RANLIB) lib610comp/libsidh.a

lib751comp: $(OBJECTS_751_COMP)
	rm -rf lib751comp sike751_compressed sidh751_compressed
	mkdir lib751comp sike751_compressed sidh751_compressed
	$(AR) lib751comp/libsidh.a $^
	$(RANLIB) lib751comp/libsidh.a

tests: lib434 lib434comp lib503 lib503comp lib610 lib610comp lib751 lib751comp
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
	$(CC) $(CFLAGS) -L./lib434comp tests/test_SIDHp434_compressed.c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh434_compressed/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib503comp tests/test_SIDHp503_compressed.c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh503_compressed/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib610comp tests/test_SIDHp610_compressed.c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh610_compressed/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib751comp tests/test_SIDHp751_compressed.c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh751_compressed/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib434comp tests/test_SIKEp434_compressed.c tests/test_extras.c -lsidh $(LDFLAGS) -o sike434_compressed/test_SIKE $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib503comp tests/test_SIKEp503_compressed.c tests/test_extras.c -lsidh $(LDFLAGS) -o sike503_compressed/test_SIKE $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib610comp tests/test_SIKEp610_compressed.c tests/test_extras.c -lsidh $(LDFLAGS) -o sike610_compressed/test_SIKE $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib751comp tests/test_SIKEp751_compressed.c tests/test_extras.c -lsidh $(LDFLAGS) -o sike751_compressed/test_SIKE $(ARM_SETTING)

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

lib434comp_for_KATs: $(OBJECTS_434_COMP) $(AES_OBJS)
	$(AR) lib434comp/libsidh_for_testing.a $^
	$(RANLIB) lib434comp/libsidh_for_testing.a

lib503comp_for_KATs: $(OBJECTS_503_COMP) $(AES_OBJS)
	$(AR) lib503comp/libsidh_for_testing.a $^
	$(RANLIB) lib503comp/libsidh_for_testing.a

lib610comp_for_KATs: $(OBJECTS_610_COMP) $(AES_OBJS)
	$(AR) lib610comp/libsidh_for_testing.a $^
	$(RANLIB) lib610comp/libsidh_for_testing.a

lib751comp_for_KATs: $(OBJECTS_751_COMP) $(AES_OBJS)
	$(AR) lib751comp/libsidh_for_testing.a $^
	$(RANLIB) lib751comp/libsidh_for_testing.a

KATS: lib434_for_KATs lib503_for_KATs lib610_for_KATs lib751_for_KATs lib434comp_for_KATs lib503comp_for_KATs lib610comp_for_KATs lib751comp_for_KATs
	$(CC) $(CFLAGS) -L./lib434 tests/PQCtestKAT_kem434.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike434/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib503 tests/PQCtestKAT_kem503.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike503/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib610 tests/PQCtestKAT_kem610.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike610/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib751 tests/PQCtestKAT_kem751.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike751/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib434comp tests/PQCtestKAT_kem434_compressed.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike434_compressed/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib503comp tests/PQCtestKAT_kem503_compressed.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike503_compressed/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib610comp tests/PQCtestKAT_kem610_compressed.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike610_compressed/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib751comp tests/PQCtestKAT_kem751_compressed.c tests/rng/rng.c -lsidh_for_testing $(LDFLAGS) -o sike751_compressed/PQCtestKAT_kem $(ARM_SETTING)

check: tests

test434:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 sike434/test_SIKE
else
	sike434/test_SIKE
endif

test503:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 sike503/test_SIKE
else
	sike503/test_SIKE
endif

test610:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 sike610/test_SIKE
else
	sike610/test_SIKE
endif

test751:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 sike751/test_SIKE
else
	sike751/test_SIKE
endif

.PHONY: clean

clean:
	rm -rf *.req objs434* objs503* objs610* objs751* objs lib434* lib503* lib610* lib751* sidh434* sidh503* sidh610* sidh751* sike434* sike503* sike610* sike751* arith_tests-*

