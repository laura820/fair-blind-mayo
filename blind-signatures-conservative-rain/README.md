For most of the details refer to the higher-level README.
There is a dedicated README for the benchmarks.

# Tests
The standard rust stack size is not large enough to handle all transformations, sppecifically those in MAYO-C, which means that in order to execute the tests, the code needs be run using an increased stack size, e.g. ```RUST_MIN_STACK=8388608 cargo test```.