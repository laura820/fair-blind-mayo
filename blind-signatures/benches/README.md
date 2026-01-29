# Benchmarking

This section briefly explains how to generate benchmarks for our implementation.
Criterion is used for general benchmarks, and flamegraph can be used to look at functions in more detail, and see which parts of the algorithms take the most time.

## Using Cargo Criterion

You only need to run ```cargo bench```, but providing more expressions you can define subsets of benchmarks that you want to run.
The updated benchmarks can be found in the ```target/criterion``` folder.
Might require running twice due to some compilation issues.

## Using Cargo Flamegraph

A flamegraph is a tool to analyse the explicit runtime of subfunctions.
This as a tool is great to see where exection time is lost.
It is mainly needed in the development process.

### Installation

1. Install cargo flamegraph: ```cargo install flamegraph```
2. Zou need perf. On WSL I did the following: Manually download the linux kernel, build perf, and then add it to the system. It can can look as follows 
```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.9.5.tar.xz
tar -xf linux-6.9.5.tar.xz
cd linux-6.9.5/tools/perf
make
cp perf /usr/local/bin/
```
However, the download of additional dependencies is needed based on the system.

### Running

The cargo flamegraph does not immediately access the build file, therefore the LD_LIBRARY_PATH is not set, and needs to be set manually.
Be aware that the files for the flamegraphs are quite large! Make sure to have enough storage. 
By how the tests are set up, each function has quite a large overhead.
If dedicated function are of interested, it is probably best to specifically analyze certain parameter sets.

```bash
export LD_LIBRARY_PATH=../mayo-c-sys/target/debug:../vole-mayo-sys/target/debug:$LD_LIBRARY_PATH
cargo flamegraph --bench blind_sig_optimized --freq 1000 --output flamegraph.svg
```
