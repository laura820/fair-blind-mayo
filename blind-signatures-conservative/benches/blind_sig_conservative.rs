use blind_signatures_conservative::{
    blind_sig_conservative::BlindSignatureConservative, zk::ZKType,
};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

pub const VARIANTS: [ZKType; 1] = [
    ZKType::FV1_128,
    // ZKType::FV1_192,
    // ZKType::FV1_256,
    // ZKType::FV2_128,
    // ZKType::FV2_192,
    // ZKType::FV2_256,
    // ZKType::SV1_128,
    // ZKType::SV1_192,
    // ZKType::SV1_256,
    // ZKType::SV2_128,
    // ZKType::SV2_192,
    // ZKType::SV2_256,
];

fn bench_sign1(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_sign1_conservative");

    let m = b"Hello World!".to_vec();

    for zktype in VARIANTS {
        let id = BenchmarkId::from_parameter(format!(
            "Bench conservative sign1 with parameters: {zktype:?}"
        ));

        group.bench_with_input(id, &zktype, |b, _| {
            b.iter_batched_ref(
                || {
                    let bs = BlindSignatureConservative::setup(zktype);
                    let (pk, _) = bs.keygen();
                    let (_judge_pk, judge_sk) = bs.keygen();
                    let judge_output = bs.reg_judge(&judge_sk);
                    let registration = bs.reg_user(&judge_output);
                    (bs, pk, registration)
                }, // setup runs once per iteration
                |(bs, pk, registration)| bs.sign_1(pk, &m, &registration.n1, &registration.sigj_n1), // only this is timed
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_sign2(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_sign2_conservative");

    let m = b"Hello World!".to_vec();

    for zktype in VARIANTS {
        let id = BenchmarkId::from_parameter(format!(
            "Bench conservative sign2 with parameters: {zktype:?}"
        ));

        group.bench_with_input(id, &zktype, |b, _| {
            b.iter_batched_ref(
                || {
                    let bs = BlindSignatureConservative::setup(zktype);
                    let (pk, sk) = bs.keygen();
                    let (judge_pk, judge_sk) = bs.keygen();
                    let registration = bs.reg_user(&bs.reg_judge(&judge_sk));
                    let (s1, n1, sigj_n1, _) =
                        bs.sign_1(&pk, &m, &registration.n1, &registration.sigj_n1);
                    (bs, sk, judge_pk, s1, n1, sigj_n1)
                }, // setup runs once per iteration
                |(bs, sk, judge_pk, s1, n1, sigj_n1)| bs.sign_2(sk, s1, n1, sigj_n1, judge_pk), // only this is timed
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_sign3(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_sign3_conservative");

    let m = b"Hello World!".to_vec();
    let additional_r: [u8; 32] = [0xff; 32];

    for zktype in VARIANTS {
        let id = BenchmarkId::from_parameter(format!(
            "Bench conservative sign3 with parameters: {zktype:?}"
        ));

        group.sample_size(10);

        group.bench_with_input(id, &zktype, |b, _| {
            b.iter_batched_ref(
                || {
                    let bs = BlindSignatureConservative::setup(zktype);
                    let (pk, sk) = bs.keygen();
                    let (judge_pk, judge_sk) = bs.keygen();
                    let epk = bs.mayo.expand_pk(&pk);
                    let registration = bs.reg_user(&bs.reg_judge(&judge_sk));
                    let (s1, n1, sigj_n1, state) =
                        bs.sign_1(&pk, &m, &registration.n1, &registration.sigj_n1);
                    let bsig = bs.sign_2(&sk, &s1, &n1, &sigj_n1, &judge_pk);
                    (bs, epk, bsig, state, registration)
                }, // setup runs once per iteration
                |(bs, epk, bsig, state, registration)| {
                    bs.sign_3(
                        epk,
                        bsig,
                        &mut state.clone(),
                        &mut additional_r.clone(),
                        &registration.pi_n1,
                        &registration.n2,
                        &registration.sigj_n2,
                    )
                }, // only this is timed
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_verify_conservative");

    let m = b"Hello World!".to_vec();
    let additional_r: [u8; 32] = [0xff; 32];

    for zktype in VARIANTS {
        let id = BenchmarkId::from_parameter(format!(
            "Bench conservative verify with parameters: {zktype:?}"
        ));

        group.sample_size(10);

        group.bench_with_input(id, &zktype, |b, _| {
            b.iter_batched_ref(
                || {
                    let bs = BlindSignatureConservative::setup(zktype);
                    let (pk, sk) = bs.keygen();
                    let (judge_pk, judge_sk) = bs.keygen();
                    let mut epk = bs.mayo.expand_pk(&pk);
                    let registration = bs.reg_user(&bs.reg_judge(&judge_sk));
                    let (s1, n1, sigj_n1, state) =
                        bs.sign_1(&pk, &m, &registration.n1, &registration.sigj_n1);
                    let bsig = bs.sign_2(&sk, &s1, &n1, &sigj_n1, &judge_pk);
                    let sig = bs.sign_3(
                        &mut epk,
                        &bsig,
                        &mut state.clone(),
                        &mut additional_r.clone(),
                        &registration.pi_n1,
                        &registration.n2,
                        &registration.sigj_n2,
                    );
                    (bs, judge_pk, epk, sig, registration)
                }, // setup runs once per iteration
                |(bs, judge_pk, epk, sig, registration)| {
                    bs.verify(
                        judge_pk,
                        epk,
                        &m,
                        sig,
                        &mut additional_r.clone(),
                        &registration.pi_n1,
                        &registration.beta,
                    )
                }, // only this is timed
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    bench_conservative,
    bench_sign1,
    bench_sign2,
    bench_sign3,
    bench_verify
);
criterion_main!(bench_conservative);
