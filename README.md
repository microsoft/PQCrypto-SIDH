# SIDH v2.0 (C Edition)

The **SIDH v2.0** library is a supersingular isogeny-based cryptography library that implements a new suite of algorithms for a post-quantum, ephemeral Diffie-Hellman key exchange scheme [2].

The library was developed by [Microsoft Research](http://research.microsoft.com/) for experimentation purposes. 

SECURITY NOTE: the scheme is NOT secure when using static keys.

## Contents

* [`SIDH.sln`](Visual%20Studio/SIDH/SIDH.sln): Visual Studio 2015 solution file for compilation in Windows.
* [`kex_tests folder`](Visual%20Studio/kex_tests/): Visual Studio 2015 test project for the key exchange.
* [`arith_tests folder`](Visual%20Studio/arith_tests/): Visual Studio 2015 test project for the low-level arithmetic, curve and isogeny functions.
* [`makefile`](makefile): Makefile for compilation using the GNU GCC or clang compilers on Linux. 
* Main library .c and .h files: main library C and header files. Public API for key exchange is located in [`SIDH_api.h`](SIDH_api.h).
* [`Optimized x64 implementation`](AMD64/): optimized implementation of the field arithmetic for x64 platforms.        
* [`Optimized ARMv8 implementation`](ARM64/): optimized implementation of the field arithmetic for ARMv8 platforms.
* [`Generic implementation`](generic/): implementation of the field arithmetic in portable C.
* [`Test folder`](tests/): test files.
* [`Magma folder`](SIDH-Magma/): Magma scripts.
* [`License`](LICENSE): MIT license file.
* [`Readme`](README.md): this readme file.

## Contributions

The field arithmetic implementation for 64-bit ARM processors ([`ARM64 folder`](AMD64/)) was contributed and is copyrighted by David Urbanik (dburbani@uwaterloo.ca).

## Main Features

- Supports ephemeral Diffie-Hellman key exchange.
- Supports a peace-of-mind hybrid key exchange mode that adds a classical elliptic curve Diffie-Hellman key exchange on a high-security Montgomery curve providing 384 bits of classical ECDH security.
- Protected against timing and cache-timing attacks through regular, constant-time implementation of all operations on secret key material.
- Support for Windows using Microsoft Visual Studio and Linux using GNU GCC and clang.     
- Provides basic implementation of the underlying arithmetic functions using portable C to enable support on a wide range of platforms including x64, x86 and ARM. 
- Provides an optimized implementation of the underlying arithmetic functions for x64 platforms with optional, high-performance x64 assembly for Linux. 
- Provides an optimized implementation of the underlying arithmetic functions for 64-bit ARM platforms using assembly for Linux.
- Includes testing and benchmarking code for key exchange. See [`kex_tests.c`](tests/kex_tests.c).

## New in Version 2.0

- A new variant of the isogeny-based key exchange that includes a new suite of algorithms for efficient public key compression [3]. In this variant, public keys are only 330 bytes (compare to 564 bytes required by the original SIDH key exchange variant without compression).  
- An optimized implementation of the underlying arithmetic functions for 64-bit ARM (ARMv8) platforms.

## Supported Platforms

**SIDH v2.0** is supported on a wide range of platforms including x64, x86 and ARM devices running Windows or Linux. We have tested the library with Microsoft Visual Studio 2015, GNU GCC v4.9, and clang v3.8.

See instructions below to choose an implementation option and compile on one of the supported platforms.

## User-Provided Functions

**SIDH** requires the user to provide a pseudo-random generator passing random values as octets to generate private keys during a key exchange (see how the PRNG function, called `RandomBytesFunction`, is used in `random_mod_order()` in [`SIDH_setup.c`](SIDH_setup.c)). This function should be provided to `SIDH_curve_initialize()` during initialization. Follow [`kex_tests.c`](tests/kex_tests.c) (see `cryptotest_kex()`) as an example on how to perform this initialization. 

An (unsafe) example function is provided in [`test_extras.c`](tests/test_extras.c) for testing purposes (see `random_bytes_test()`). NOTE THAT THIS SHOULD NOT BE USED IN PRODUCTION CODE. 

Finally, the outputs of the shared secret functions are not processed by a key derivation function (e.g., a hash). The user is responsible for post-processing to derive cryptographic keys from the shared secret (e.g., see [NIST Special Publication 800-108](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)).     

## Implementation Options

 The following implementation options are available:
- Portable implementation enabled by the "GENERIC" option, and an optimized x64 implementation. 
- Optimized x64 assembly implementation for Linux.
- Optimized ARMv8 assembly implementation for Linux.

Note that, excepting x64 and ARMv8, platforms are only supported by the generic implementation. 

Follow the instructions in the sections "_Instructions for Windows_" or "_Instructions for Linux_" below to configure these different implementation options.

## Instructions for Windows

### Building the library with Visual Studio:

Open the solution file ([`SIDH.sln`](Visual%20Studio/SIDH/SIDH.sln)) in Visual Studio, and select one of the supported platforms as Platform. Then choose a configuration from the configuration menu: for x64, one can select either "Release" (faster) or "Generic"; for other platforms, choose "Generic". Finally, select "Build Solution" from the "Build" menu. 

### Running the tests:

After building the solution file, there should be two executable files available: `arith_tests.exe`, to run tests for the underlying arithmetic, and `kex_tests.exe`, to run tests for key exchange. 

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
