# Concretely efficient blind signatures based on VOLE-in-the-head proofs and the MAYO trapdoor

## Overview

This repository contains an implementation of blind signature (BS) scheme. It implements the following constructions.

- BS from SHAKE256 + MAYO
    - (1) SHAKE256 with commitments in every round (blind-signatures-conservative)
    - (2) SHAKE256 with commitments in every 6th round, 4 rounds forward and 2 rounds backward (blind-signatures-deg16)
- BS from RainHash + MAYO
    - (3) Rainhash with commitments in every round, total 7 rounds (blind-signatures-conservative-rain)
- BS from One-More-MAYO
    - uses MAYO preimage sampling MAYO signature scheme (blind-signatures)

The VOLEith technique is used from the NIST round 1 submission of [FAEST](https://FAEST.info/) and combined with the round 2 submission of [MAYO](https://github.com/PQCMayo/MAYO-C).
The repository utilizes three different parameter sets of MAYO: MAYO1, MAYO3, and MAYO5, referring to 128, 192, and 256-bit security.
These are combined with the VOLEith proof framework from FAEST, which has 2 versions for each security level: fast (larger proof size with smaller runtime) and small (smaller proof size with larger runtime).

## Project Structure
```
PQ_BLIND_SIGNATURES/                        # a simplified overview
├── blind-signatures/                       # One-More MAYO
 ├── src/
 └── benches/
├── blind-signatures-conservative/          # SHAKE256 + MAYO (1)
 ├── src/
 └── benches/
├── blind-signatures-conservative-deg16/    # SHAKE256-Deg16 + MAYO (2)
 ├── src/
 └── benches/
├── blind-signatures-conservative-rain/     # RainHash + MAYO (3)
 ├── src/
 └── benches/
├── mayo-c-sys/                             # FFI for MAYO
├── vole-mayo-sys/                          # FFI for ZK proof MAYO
├── vole-keccak-then-mayo-sys/              # FFI for ZK proof KECCAK + MAYO
├── vole-keccak-deg16-then-mayo-sys/        # FFI for ZK proof KECCAK(deg 16) + MAYO
├── vole-keccak-deg16-then-mayo-sys/        # FFI for ZK proof RainHash + MAYO
├── vole/                                   # C++ ZK proofs
 ├── FAEST-cpp-tmp/                         # build folder with shared files
 ├── optimized_bs/                          # contains MAYO blind signature files
 ├── conservative_bs/                       # contains KECCAK(-Deg16) and RainHash + MAYO blind signature files
 ├── build_consv_bs_keccak_deg16.sh         # compiles KECCAK-Deg16 + MAYO BS
 ├── build_consv_bs_keccak.sh               # compiles KECCAK + MAYO BS
 ├── build_consv_bs_rainhash.sh             # compiles RainHash + MAYO BS
 ├── build_opti_bs.sh                       # compiles MAYO BS
├── bench.sh                                # For benchmarking all blind-signatures
└── bench_log.txt                           # contains benchmarking results
```

The constructions in this work utilize highly optimized frameworks in different programming languages (C and C++) designed as standalones.
We combine these libraries through a foreign function interface (FFI) to Rust, where we connect the building blocks, implement the blind signatures, and benchmark the constructions.
The FFIs are generated using [bindgen](https://github.com/rust-lang/rust-bindgen) and provide an interface to MAYO and the circuit implementations.
For MAYO, the FFI can be found in `mayo-c-sys`.
For each of the zk proof circuits, there is a dedicated FFI: `vole-mayo-sys`, `vole-keccak-then-mayo-sys`, and `vole-keccak-deg16-then-mayo-sys` and `vole-rainhash-then-mayo-sys`.

These FFIs compile and build the underlying C/C++ libraries, generate a shared library file, and generate bindings to an additionally defined public interface file.
This allows the usage of these functions when including them in the respective Rust projects.

The zk proof circuits are found in the `vole` folder and all use the same underlying FAEST code with the additional modifications needed to implement the circuits themselves.
As they are all using the same framework, building the libraries/FFIs at the same time is **not possible**.
Therefore, we have separate Rust libraries for each of the actual implementations of the blind signatures.

### Modifications of other Libraries

The changes to FAEST are inherent because there, the circuits for MAYO, Keccak, and Rain were not present.
Nevertheless, we also needed to make some additions to other libraries that we briefly describe here.
- MAYO: `mayo-c-sys/mayo_without_hashing.c`
    - `mayo_sign_without_hashing`: A sign that just calls the preimage sampling function and also includes no salt
    - `mayo_sign_fixed_length_input`: A sign that expects a fixed-length message input and therefore does not hash the initial message to a fixed length
- MAYO: `mayo-c-rain-sys`: We replaced the internal hash functions in the signature scheme with the RAINHASH, but it is the same otherwise.
- SHAKE256: `vole/common/fips202.c`:
    - `shake256_w`: Normal shake where each intermediate S is written to a witness. The construction does not provide an explicit output and outputs the S of the final round, from where a hash output of up to the SHAKE256 rate can be extracted
        - also has the modification to only output the intermediate S values from every 6th round

### ZK Proofs using the FAEST Framework

The most important parts of the zk proofs are in the `owf_proof.inc` files.
We briefly describe them here for the interested reader:

- `vole/optimized_bs/owf_proof.inc`: `enc_constraints`
    - loads the witness of the randomness and the signature, and the hash value
    - compute $t = h \oplus r$
    - MAYO map evaluation for signature, where the provided MAYO-public key is round-wise modified to mimic the behavior of the $E^\ell$ multiplication in the map evaluation.
    - add constraints between map evaluation and $t$
- `vole/consevative_bs/owf_proof.inc`: `enc_constraints`
    - performs adds constraints for shake256 and MAYO, more precisely: one for the initial commitment, one for the hashing in the MAYO signature scheme, and one map evaluation for MAYO.
 The witnesses are the randomness for the commitment, the S from every 1th/6th round of keccak, the commitment and the salt used in the MAYO signature, and the MAYO signature itself.
    - `enc_constraints_keccak`:
        - in the plain version: `enc_constraints_fwd_one_full_round`: performs all 24 rounds and adds a degree 2 check in between every single round
        - In the deg16 version, there are forward and backward constraints: the witness provides the values from every 6th round. From each of them, we can compute the Keccak permutations *and* their inverse. This way, we can check if the commitments match in the middle of each of the 6 rounds and have a smaller degree check of only degree 16.
    - `enc_constraints_mayo`: behaves essentially the same as the enc_constraints function from `vole/mayo/owf_proof.inc` with the exception that the target is loaded in directly and no xor with some randomness needs to be performed
    - `enc_constraints_rainhash`:
        - contains the RainHash constraints for 7 rounds RainHash with deg2 check every round
- `vole/keccak_then_mayo_bs/owf_proof.inc`: `enc_constraints`

## Requirements and Installation

We constructed the project using Ubuntu 24.04 on WSL with the following requirements.

- gcc >= 14.2.0
- meson >= 1.7.0 (installation via pipx)
- ninja >= 1.12.1. (manual build needed)
- download Rust
- download libclang
- gnuplot (for benchmarking using criterion)
- cmake >= 3.28.3 (tested version) (needed for rainhash)
- preferably run in vs code terminal, manages env and other dependencies automatically

We have a separate small installation guide, where we ran our code on a fresh installation of Ubuntu 24.04 on WSL.
The file is [here](manual-installation.md).

## Minimal Working Example

After having finished the previous installation guide, you can run our code.
If you have not already reproduced our results using `./bench.sh`, you can also run a small sanity check making sure all of the compilations work by navigating to `blind-signatures-conservative-deg16` and running `RUST_MIN_STACK=8388608 cargo test test_and_bench_sign_loop_conservative_128fv1`.

## Build

For the intermediate constructions, there are explicit build files such as
`vole/build_opti_bs.sh`, `build_consv_bs_keccak.sh`, `build_consv_bs_keccak_deg16.sh` and `build_consv_bs_rainhash.sh`. For the FFI to MAYO, this build file is merged into `mayo-c-sys/Makefile`.

To build the blind signatures themselves, go to the respective construction of choice:
`blind-signatures` (optmized bs), `blind-signatures-conservative`, `blind-signatures-conservative-deg16`, `blind-signatures-conservative-rain` or `blind-signatures-conservative-rain-deg16` and run `cargo build` *or* just run tests directly.
There, you can, for instance, execute the tests implemented within the code with the command: `cargo test`. **However**, the default stack size in Rust is not sufficient for the map evaluations in MAYO, so when running the tests, the stack size needs to be adjusted manually, e.g., `RUST_MIN_STACK=8388608 cargo test`.

### Did you get this Repository as a ZIP Folder?

This project is initialized with git submodules and designed to be compiled using git submodules.
Hence, when you get this project as a ZIP folder the build naturally fails.
Here is what you can do to fix it after you unzipped this repository:
1. Manually download the MAYO-C repository ```git clone git@github.com:PQCMayo/MAYO-C.git```
2. Comment out the ```update_submodules``` command in ```mayo-c-sys/Makefile``` (because it is not linked as a submodule anymore)
3. The build scripts in the ```vole``` folder do not have execution rights anymore, so they need to be allowed to be executed, using ```chmod +x build_consv_bs_keccak_deg16.sh```, ```chmod +x build_consv_bs_keccak.sh```, ```chmod +x build_consv_bs_rainhash.sh``` or ```chmod +x build_opti_bs.sh``` depending on the construction that you want to test. 
4. For the benchmark script also add ```chmod +x bench.sh``` in the main directory. Also note, the `bench.sh` script itself adds the above permissions if one runs it.
5. Simply run `bench.sh` to get the benchmark numbers in `bench_log.txt` (easiest option!). This may tke several minutes depending on the machine. View `bench_log_misc.txt` and the terminal for compile and bench progress. The benchmarks themselves also act as test-cases verifying the final blind signatures.

As mentioned in the next chapter, all constructions use the same buildfolder for the C++ library so sometimes it is required to clean the build repository using the ```clean.sh``` script which also needs to be made executable.
When we tried compiled it from a ZIP folder we found that we had to call ```cargo bench``` more than once when we compiled for the first time, because meson, with which we compile the C++ code blocked it on the first try, because the folder was already registered with the other construction that was build previously.

### Problems with Building or Running Tests?

As all the circuits share the same build file for the underlying circuit, there sometimes appear to be problems in the build process.
As a solution, you can change into the `vole` folder and run `./clean.sh` and then build the library manually first. This way, the folder is reset.
The FFIs build the shared library and make it accessible to Rust.
Therefore, changing something in the circuit and then only building in C++ *does not* propagate these changes to the Rust part.
The FFIs need to be cleaned too: change into the desired FFI folder and run `cargo clean`.
Once they are cleaned, go back to the desired rust construction, run `cargo clean`, and try building it again.

## Benchmarks

Easiest option:
Just run `bench.sh`, grab a coffee and relax! Bench results are output in `bench_log.txt`. The miscellanenous bench results are output in `bench_log_misc.txt`. `bench.sh` may need ```chmod +x``` permission on first run as discussed above. Depending on the machine the full benching may some minutes. View `bench_log_misc.txt` and the terminal for compile and bench progress. The benchmarks themselves also act as test-cases verifying the final blind signatures

### More detailed Benchmarks

The same build tips from the previous section apply.
The benchmarks utilize [criterion](https://bheisler.github.io/criterion.rs/book/cargo_criterion/cargo_criterion.html).
To run the benchmarks, run `cargo bench` and potentially limit the constructions to those desired to be benchmarked.

For each construction, there are a total of 4 benchmarks: (1) sign1, (2) sign2, (3) sign3, and (4) verify.
Each of these runs the benchmark for each of the parameter sets.
If you only want to run the benchmarks for a subset, you can comment out the variants that you do not want to benchmark.
The benchmarks are then saved to the `target/criterion` folder, where the report can be viewed as an HTML file.