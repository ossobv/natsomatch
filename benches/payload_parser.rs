use criterion::{black_box, criterion_group, criterion_main, Criterion};

use nats2jetstream::payload_parser;


fn criterion_benchmark(c: &mut Criterion) {
    let jsb = br#"{"attributes":{"something":"more_something","section":"the_section"},"other":true}"#;

    c.bench_function("get_section_safe", |b| {
        b.iter(|| payload_parser::get_section_safe(black_box(jsb)))
    });
    c.bench_function("get_section_fast", |b| {
        b.iter(|| payload_parser::get_section_fast(black_box(jsb)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
