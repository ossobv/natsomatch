use criterion::{black_box, criterion_group, criterion_main, Criterion};

use nats2jetstream::payload_parser;


fn criterion_benchmark(c: &mut Criterion) {
    let jsb =
        br#"{"attributes":{"something":"more_something","section":"the_section","host":"mgmt.example"}
            ,"message":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ,"somedict":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21]
            ,"timestamp":"2024-02-16T15:45:16.266891180Z"}"#;

    c.bench_function("get_section_safe", |b| {
        b.iter(|| payload_parser::get_section_safe(black_box(jsb)))
    });
    c.bench_function("get_section_fast", |b| {
        b.iter(|| payload_parser::get_section_fast(black_box(jsb)))
    });
    c.bench_function("get_attributes", |b| {
        b.iter(|| payload_parser::get_attributes(black_box(jsb)))
    });
    c.bench_function("Attributes constructor", |b| {
        b.iter(|| payload_parser::Attributes::from_payload(black_box(jsb)))
    });
    let attrs = payload_parser::Attributes::from_payload(jsb);
    c.bench_function("Attributes.get_unique_id", |b| {
        b.iter(|| attrs.get_unique_id());
    });
    c.bench_function("Attributes2 constructor", |b| {
        b.iter(|| payload_parser::Attributes2::from_payload(black_box(jsb)))
    });
    let attrs2 = payload_parser::Attributes2::from_payload(jsb);
    c.bench_function("Attributes2.get_unique_id", |b| {
        b.iter(|| attrs2.get_unique_id());
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
