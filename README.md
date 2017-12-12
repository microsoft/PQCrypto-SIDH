# SIDH v3.0 (C Edition)

The **SIDH** library is an efficient supersingular isogeny-based cryptography library written in C language.
**Version v3.0** of the library includes the ephemeral Diffie-Hellman key exchange scheme "SIDH" [1,2], and the CCA-secure
key encapsulation mechanism "SIKE" [4]. These schemes are conjectured to be secure against quantum computer attacks.

Concretely, the SIDH library includes the following KEM schemes:

* SIKEp503: matching the post-quantum security of AES128.
* SIKEp751: matching the post-quantum security of AES192.

And the following ephemeral key exchange schemes:

* SIDHp503: matching the post-quantum security of AES128.
* SIDHp751: matching the post-quantum security of AES192.

The library was developed by [Microsoft Research](http://research.microsoft.com/) for experimentation purposes.

## Contents

* [`KAT folder`](KAT/): Known Answer Test (KAT) files for the KEM.
* [`src folder`](src/): C and header files. Public APIs can be found in [`P503_api.h`](src/P503/P503_api.h) and [`P751_api.h`](src/P751/P751_api.h).
* [`Optimized x64 implementation for p503`](src/P503/AMD64/): optimized implementation of the field arithmetic over the prime p503 for x64 platforms. 
* [`Optimized x64 implementation for p751`](src/P751/AMD64/): optimized implementation of the field arithmetic over the prime p751 for x64 platforms.      
* [`Optimized ARMv8 implementation for p751`](src/P751/ARM64/): optimized implementation of the field arithmetic over the prime p751 for ARMv8 platforms.
* [`Generic implementation for p503`](src/P503/generic/): implementation of the field arithmetic over the prime p503 in portable C.
* [`Generic implementation for p751`](src/P751/generic/): implementation of the field arithmetic over the prime p751 in portable C.
* [`random folder`](src/random/): randombytes function using the system random number generator.
* [`sha3 folder`](src/sha3/): cSHAKE256 implementation.  
* [`Test folder`](tests/): test files.   
* [`Visual Studio folder`](Visual%20Studio/): Visual Studio 2015 files for compilation in Windows.
* [`Makefile`](Makefile): Makefile for compilation using the GNU GCC or clang compilers on Linux. 
* [`License`](LICENSE): MIT license file.
* [`Readme`](README.md): this readme file.

## Main Features

- Supports IND-CCA secure key encapsulation mechanism.
- Supports ephemeral Diffie-Hellman key exchange.
- Supports two security levels matching the post-quantum security of AES128 and AES192.
- Supports a peace-of-mind hybrid key exchange mode that adds a classical elliptic curve Diffie-Hellman 
  key exchange on a high-security Montgomery curve providing 384 bits of classical ECDH security.
- Protected against timing and cache-timing attacks through regular, constant-time implementation of 
  all operations on secret key material.
- Support for Windows OS using Microsoft Visual Studio and Linux OS using GNU GCC and clang.     
- Provides basic implementation of the underlying arithmetic functions using portable C to enable support
  on a wide range of platforms including x64, x86 and ARM . 
- Provides optimized implementations of the underlying arithmetic functions for x64 platforms with optional, 
  high-performance x64 assembly for Linux. 
- Provides an optimized implementation of the underlying arithmetic functions for 64-bit ARM platforms using 
  assembly for Linux.
- Includes Known Answer Tests (KATs), and testing/benchmarking code.

## New in Version 3.0

- Added support for SIKE [4], an IND-CCA secure key encapsulation protocol based on supersingular isogenies.
- Added a new parameter set over the prime p503 that matches the post-quantum security of AES128.
- The implementations are significantly more compact and faster. Among other optimizations, the library exploits a new tripling formula from [5] and the fast three-point ladder algorithm from [6].  
- Removed the code implementing public key compression [3]. 
The old compression code can be accessed [here](https://github.com/Microsoft/PQCrypto-SIDH/tree/v2.0).
Note that a faster compression implementation [7] is available in a [fork of SIDH](https://github.com/Microsoft/PQCrypto-SIDH/tree/v2.0). 
In this case, public keys are reduced from 564 to 330 bytes, but the computing time suffers almost a two-fold slowdown.
- Added Known Answer Tests (KATs).

## Supported Platforms

**SIDH v3.0** is supported on a wide range of platforms including x64, x86 and ARM devices running Windows 
or Linux OS. We have tested the library with Microsoft Visual Studio 2015, GNU GCC v5.4, and clang v3.8.
See instructions below to choose an implementation option and compile on one of the supported platforms.

## Implementation Options

 The following implementation options are available:
- Portable implementations enabled by setting `OPT_LEVEL=GENERIC`. 
- Optimized x64 assembly implementations for Linux enabled by setting `ARCH=x64` and `OPT_LEVEL=FAST`.
- Optimized ARMv8 assembly implementation for Linux enabled by setting `ARCH=ARM64` and `OPT_LEVEL=FAST`.

Follow the instructions in the sections "_Instructions for Linux_" or "_Instructions for Windows_" below to configure these different implementation options.

## Instructions for Linux

By simply executing:

```sh
$ make
```

the library is compiled for x64 using clang, optimization level `FAST`, and using the special instructions MULX
and ADX. Optimization level `FAST` enables the use of assembly, which in turn is a requirement to enable the 
optimizations using MULX/ADX.

Other options for x64:

```sh
$ make ARCH=x64 CC=[gcc/clang] OPT_LEVEL=[FAST/GENERIC] USE_MULX=[TRUE/FALSE] USE_ADX=[TRUE/FALSE] SET=[EXTENDED]
```

Setting `SET=EXTENDED` adds the flags `-fwrapv -fomit-frame-pointer -march=native`. When `OPT_LEVEL=FAST` (i.e., 
assembly use enabled), the user is responsible for setting the flags MULX and ADX according to the targeted 
platform (for example, MULX/ADX are not supported on Sandy or Ivy Bridge, only MULX is supported on Haswell, 
and both MULX and ADX are supported on Broadwell, Skylake and Kaby Lake architectures). Note that USE_ADX can 
only be set to `TRUE` if `USE_MULX=TRUE`.

Options for x86/ARM:

```sh
$ make ARCH=[x86/ARM] CC=[gcc/clang] SET=[EXTENDED]
```

Options for ARM64:

```sh
$ make ARCH=[ARM64] CC=[gcc/clang] OPT_LEVEL=[FAST/GENERIC] SET=[EXTENDED]
```

As in the x64 case, `OPT_LEVEL=FAST` enables the use of assembly optimizations on ARMv8 platforms.

Different tests and benchmarking results are obtained by running:

```sh
$ ./arith_tests-p503
$ ./arith_tests-p751
$ ./sike503/test_SIKE
$ ./sike751/test_SIKE
$ ./sidh503/test_SIDH
$ ./sidh751/test_SIDH
```

To run the KEM implementations against the KATs, execute:

```sh
$ ./sike503/PQCtestKAT_kem
$ ./sike751/PQCtestKAT_kem
```

The program tries its best at auto-correcting unsupported configurations. For example, since the `FAST` implementation is currently only available for x64 and ARMv8 doing `make ARCH=x86 OPT_LEVEL=FAST` is actually processed using `ARCH=x86 OPT_LEVEL=GENERIC`.

## Instructions for Windows

### Building the library with Visual Studio:

Open the solution file [`SIDH.sln`](Visual%20Studio/SIDH/SIDH.sln) in Visual Studio, choose either x64 or Win32 from the platform menu and then choose either `Fast` or `Generic` from the configuration menu (as explained above, the option `Fast` is not currently available for x86). Finally, select "Build Solution" from the "Build" menu. 

### Running the tests:

After building the solution file, there should be 6 executable files: `arith_tests-P503.exe` and `arith_tests-P751.exe`, to run tests for the underlying arithmetic, `test-SIDHp503.exe` and `test-SIDHp751.exe`, to run tests for the key exchange, and `test-SIKEp503.exe` and `test-SIKEp751.exe`, to run tests for the KEM. 

### Using the library:

After building the solution file, add the generated `P503.lib` and `P751.lib` library files to the set of References for a project, and add [`P503_api.h`](src/P503/P503_api.h) and [`P751_api.h`](src/P751/P751_api.h) to the list of header files of a project.

## License

**SIDH** is licensed under the MIT License; see [`License`](LICENSE) for details.

The library includes some third party modules that are licensed differently. In particular:

- `tests/aes/aes_c.c`: public domain
- `tests/rng/rng.c`: copyrighted by Lawrence E. Bassham 
- `tests/PQCtestKAT_kem<#>.c`: copyrighted by Lawrence E. Bassham 
- `src/sha3/fips202.c`: public domain

## Contributors

The field arithmetic implementation for 64-bit ARM processors ([`ARM64 folder`](src/P751/ARM64/)) was contributed and is copyrighted by David Urbanik (dburbani@uwaterloo.ca).

Other contributors include:

- Joost Renes, while he was an intern with Microsoft Research.

# References

[1]  Craig Costello, Patrick Longa, and Michael Naehrig, "Efficient algorithms for supersingular isogeny Diffie-Hellman". Advances in Cryptology - CRYPTO 2016, LNCS 9814, pp. 572-601, 2016. 
The extended version is available [`here`](http://eprint.iacr.org/2016/413). 

[2]  David Jao and Luca DeFeo, "Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies". PQCrypto 2011, LNCS 7071, pp. 19-34, 2011. 

[3]  Craig Costello, David Jao, Patrick Longa, Michael Naehrig, Joost Renes, and David Urbanik, "Efficient compression of SIDH public keys". Advances in Cryptology - EUROCRYPT 2017, LNCS 10210, pp. 679-706, 2017. 
The preprint version is available [`here`](http://eprint.iacr.org/2016/963).

[4]   Reza Azarderakhsh, Matthew Campagna, Craig Costello, Luca De Feo, Basil Hess, Amir Jalali, David Jao, Brian Koziel, Brian LaMacchia, Patrick Longa, Michael Naehrig, Joost Renes, Vladimir Soukharev, and David Urbanik, "Supersingular Isogeny Key Encapsulation". Submission to the NIST Post-Quantum Standardization project (to appear soon), 2017.  

[5]  Craig Costello, and Huseyin Hisil, "A simple and compact algorithm for SIDH with arbitrary degree isogenies". Advances in Cryptology - ASIACRYPT 2017 (to appear), 2017. 
The preprint version is available [`here`](https://eprint.iacr.org/2017/504). 

[6]  Armando Faz-Hernández, Julio López, Eduardo Ochoa-Jiménez, and Francisco Rodríguez-Henríquez, "A faster software implementation of the supersingular isogeny Diffie-Hellman key exchange protocol". Cryptology ePrint Archive: Report 2017/1015, 2017. 
The preprint version is available [`here`](https://eprint.iacr.org/2017/1015). 

[7]  Gustavo H. M. Zanon, Marcos A. Simplicio Jr., Geovandro C. C. F. Pereira, Javad Doliskani, and Paulo S. L. M. Barreto, "Faster isogeny-based compressed key agreement". Cryptology ePrint Archive: Report 2017/1143, 2017. 
The preprint version is available [`here`](https://eprint.iacr.org/2017/1143). 

# Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
