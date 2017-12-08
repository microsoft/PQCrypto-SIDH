# SIDH v3.0 (C Edition)

The **SIDH v3.0** library is an efficient supersingular isogeny-based cryptography library.
It implements the ephemeral Diffie-Hellman key exchange scheme "SIDH" [1,2], and the CCA-secure
key encapsulation mechanism "SIKE" []. These schemes are conjectured to offer protection against 
quantum computer attacks.

Concretely, the SIDH library includes the following KEM schemes:

* SIKEp503: matching the post-quantum security of AES128.
* SIKEp751: matching the post-quantum security of AES192.

And the following ephemeral key exchange schemes:

* SIDHp503: matching the post-quantum security of AES128.
* SIDHp751: matching the post-quantum security of AES192.

The library was developed by [Microsoft Research](http://research.microsoft.com/) for experimentation purposes.

## Contents

* [`KAT folder`](KAT/): Known Answer Test (KAT) files for the KEM.
* [`src folder`](src/): C and header files. Public APIs are located in [`P503_api.h`](src/P503/P503_api.h) and [`P751_api.h`](src/P751/P751_api.h).
* [`Optimized x64 implementation`](src/P503/AMD64/): optimized implementation of the field arithmetic over p503 for x64 platforms. 
* [`Optimized x64 implementation`](src/P751/AMD64/): optimized implementation of the field arithmetic over p751 for x64 platforms.      
* [`Optimized ARMv8 implementation`](src/P751/ARM64/): optimized implementation of the field arithmetic over P751 for ARMv8 platforms.
* [`Generic implementation`](src/P503/generic/): implementation of the field arithmetic over P503 in portable C.
* [`Generic implementation`](src/P751/generic/): implementation of the field arithmetic over P751 in portable C.
* [`random folder`](src/random/): randombytes function using system random number generator.
* [`sha3 folder`](src/sha3/): cSHAKE256 implementation.  
* [`Test folder`](tests/): test files.        
* [`Visual Studio folder`](Visual%20Studio/): Visual Studio 2015 files for compilation in Windows.
* [`Makefile`](Makefile): Makefile for compilation using the GNU GCC or clang compilers on Linux. 
* [`Magma folder`](SIDH-Magma/): Magma scripts.
* [`License`](LICENSE): MIT license file.
* [`Readme`](README.md): this readme file.

## Contributions

The field arithmetic implementation for 64-bit ARM processors ([`ARM64 folder`](src/P751/ARM64/)) was contributed and is copyrighted by David Urbanik (dburbani@uwaterloo.ca).

## Main Features

- Supports IND-CCA secure key encapsulation mechanism.
- Supports ephemeral Diffie-Hellman key exchange.
- Supports two security levels matching post-quantum security of AES128 and AES192.
- Supports a peace-of-mind hybrid key exchange mode that adds a classical elliptic curve Diffie-Hellman 
  key exchange on a high-security Montgomery curve providing 384 bits of classical ECDH security.
- Protected against timing and cache-timing attacks through regular, constant-time implementation of 
  all operations on secret key material.
- Support for Windows OS using Microsoft Visual Studio and Linux OS using GNU GCC and clang.     
- Provides basic implementation of the underlying arithmetic functions using portable C to enable support
  on a wide range of platforms including x64, x86 and ARM. 
- Provides and optimized implementation of the underlying arithmetic functions for x64 platforms with optional, 
  high-performance x64 assembly for Linux. 
- Provides an optimized implementation of the underlying arithmetic functions for 64-bit ARM platforms using 
  assembly for Linux.
- Includes Known Answer Tests (KATs), and testing/benchmarking code.

## New in Version 3.0

- Added support for SIKE, an IND-CCA secure key encapsulation protocol.
- Added a new parameter set matching the post-quantum security of AES128.
- The implementations are significantly more compact (in code size) and faster.
- Removed code implementing public key compression [3]. The old compression code [3] can still be accessed at: 

  Note that a faster compression implementation is available a fork of SIDH: 
  (public keys are reduced from 564 to 330 bytes, but the computation time is suffers a two-fold slowdown).

## Supported Platforms

**SIDH v3.0** is supported on a wide range of platforms including x64, x86 and ARM devices running Windows 
or Linux OS. We have tested the library with Microsoft Visual Studio 2015, GNU GCC v4.9, and clang v3.8.
See instructions below to choose an implementation option and compile on one of the supported platforms.

## Implementation Options

 The following implementation options are available:
- Portable implementation enabled by the "GENERIC" option, and an optimized x64 implementation. 
- Optimized x64 assembly implementation for Linux.
- Optimized ARMv8 assembly implementation for Linux.

Note that, excepting x64 and ARMv8, platforms are only supported by the generic implementation. 

Follow the instructions in the sections "_Instructions for Windows_" or "_Instructions for Linux_" below to configure these different implementation options.

## Instructions for Windows

### Building the library with Visual Studio:

Open the solution file ([`SIDH.sln`](Visual%20Studio/SIDH/SIDH.sln)) in Visual Studio, and choose either x64 or Win32 from the platform menu. The option "Fast-generic" should be selected in the configuration menu. Finally, select "Build Solution" from the "Build" menu. 

### Running the tests:

After building the solution file, there should be 4 executable files: `arith_tests.exe`, to run tests for the underlying arithmetic, and `kex_tests.exe`, to run tests for key exchange. 

### Using the library:

After building the solution file, add the generated `SIDH.lib` file to the set of References for a project, and add [`SIDH.h`](SIDH.h) and [`SIDH_api.h`](SIDH_api.h) to the list of header files of a project.

## Instructions for Linux

To compile on Linux using GNU GCC or clang, execute the following command from the command prompt:

```sh
$ make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] GENERIC=[TRUE/FALSE] SET=[EXTENDED]
```

After compilation, run `kex_test` or `arith_test`.
By default, the software is compiled using clang, as well as with the assembly-optimized implementation when ARCH is set to x64. For example, to compile using clang and the fully optimized x64 implementation in assembly, execute:

```sh
$ make ARCH=x64
```

Similarly, to compile using clang for ARMv8 execute: 

```sh
$ make ARCH=ARM64
```

As another example, to compile using GNU GCC and the portable implementation on an x86 machine, execute:

```sh
$ make ARCH=x86 CC=gcc GENERIC=TRUE
```

When SET=EXTENDED, the following compilation flags are used: `-fwrapv -fomit-frame-pointer -march=native`. Users are encouraged to experiment with different flag options.

Whenever an unsupported configuration is applied, the following message will be displayed: `#error -- "Unsupported configuration"`. For example, ARCH=x86 and ARCH=ARM are only supported when GENERIC=TRUE.

## License

**SIDH** is licensed under the MIT License; see [`License`](LICENSE) for details.

# References

[1]  Craig Costello, Patrick Longa, and Michael Naehrig, "Efficient algorithms for supersingular isogeny Diffie-Hellman". Advances in Cryptology - CRYPTO 2016, LNCS 9814, pp. 572-601, 2016. 
The extended version is available [`here`](http://eprint.iacr.org/2016/413). 

[2]  David Jao and Luca DeFeo, "Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies". PQCrypto 2011, LNCS 7071, pp. 19-34, 2011. 

[3]  Craig Costello, David Jao, Patrick Longa, Michael Naehrig, Joost Renes, and David Urbanik, "Efficient compression of SIDH public keys". Advances in Cryptology - EUROCRYPT 2017, LNCS 10210, pp. 679-706, 2017. 
The preprint version is available [`here`](http://eprint.iacr.org/2016/963). 

# Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
