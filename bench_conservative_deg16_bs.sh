
echo "Scheme - Sig1 (ms), Sig2 (ms), Sig3 (ms), Ver (ms), Comm (KB), BS (KB)" > bench_log.txt
echo "--------------------------------------------------------" >> bench_log.txt

git submodule update --init --recursive
cd vole
# Getting conservative bench
chmod +x clean.sh
./clean.sh 
chmod +x build_consv_bs_keccak.sh
./build_consv_bs_keccak.sh >> ../bench_log_misc.txt 2>&1
cd ..
cd vole-keccak-then-mayo-sys
cargo clean
cd ..
cd blind-signatures-conservative
cargo clean
# cargo test test_and_bench_sign_loop_conservative_128sv1 --no-run >> ../bench_log_misc.txt 2>&1
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_128sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_128fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt

# echo "--------------------------------------------------------" >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_192sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_192fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# echo "--------------------------------------------------------" >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_256sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_256fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt

cd ..
# echo "--------------------------------------------------------" >> bench_log.txt
# echo "--------------------------------------------------------" >> bench_log.txt
cd vole
# Getting conservative deg-16 bench
./clean.sh 
chmod +x build_consv_bs_keccak_deg16.sh
./build_consv_bs_keccak_deg16.sh >> ../bench_log_misc.txt 2>&1
cd ..
cd vole-keccak-deg16-then-mayo-sys
cargo clean
cd ..
cd blind-signatures-conservative-deg16
cargo clean
cargo test test_and_bench_sign_loop_conservative_128sv1 --no-run >> ../bench_log_misc.txt 2>&1
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_128sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_128fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
echo "--------------------------------------------------------" >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_192sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_192fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
echo "--------------------------------------------------------" >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_256sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_256fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt

# cd ..
# echo "--------------------------------------------------------" >> bench_log.txt
# echo "--------------------------------------------------------" >> bench_log.txt
# cd vole
# # Getting conservative rainhash bench
# ./clean.sh 
# chmod +x build_consv_bs_rainhash.sh
# ./build_consv_bs_rainhash.sh >> ../bench_log_misc.txt 2>&1
# cd ..
# cd vole-rainhash-then-mayo-sys
# cargo clean
# cd ..
# cd blind-signatures-conservative-rain
# cargo clean
# cargo test test_and_bench_sign_loop_conservative_rain_128sv1 --no-run >> ../bench_log_misc.txt 2>&1
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_rain_128sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_conservative_rain_128fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt

# cd ..
# echo "--------------------------------------------------------" >> bench_log.txt
# echo "--------------------------------------------------------" >> bench_log.txt
# cd vole
# # Getting optimized bench
# ./clean.sh 
# chmod +x build_opti_bs.sh
# ./build_opti_bs.sh >> ../bench_log_misc.txt 2>&1
# cd ..
# cd vole-mayo-sys
# cargo clean
# cd ..
# cd blind-signatures
# cargo clean
# cargo test test_and_bench_sign_loop_optimized_128sv1 --no-run >> ../bench_log_misc.txt 2>&1
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_128sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_128fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# echo "--------------------------------------------------------" >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_192sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_192fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# echo "--------------------------------------------------------" >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_256sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_256fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
# echo "--------------------------------------------------------" >> ../bench_log.txt
