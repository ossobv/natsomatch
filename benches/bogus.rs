use criterion::{black_box, criterion_group, criterion_main, Criterion};


fn test_bogus(input: i32) -> i32 {
    42 + input
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("test_bogus", |b| {
        b.iter(|| test_bogus(black_box(0)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
