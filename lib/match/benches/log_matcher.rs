use criterion::{black_box, criterion_group, criterion_main, Criterion};

use nats2jetstream_json::payload_parser::BytesAttributes;
use nats2jetstream_match::log_matcher::{Match, samples};


fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Match::from_attributes(samples::HAPROXY)", |b| {
        let attr = BytesAttributes::from_payload(samples::HAPROXY).unwrap();
        b.iter(|| {
            let m = Match::from_attributes(black_box(&attr)).unwrap();
            assert_eq!(m.destination, "bulk_match_haproxy");
        });
    });
    c.bench_function("Match::from_attributes(samples::UNKNOWN)", |b| {
        let attr = BytesAttributes::from_payload(samples::UNKNOWN).unwrap();
        b.iter(|| {
            let m = Match::from_attributes(black_box(&attr)).unwrap();
            assert_eq!(m.destination, "bulk_match_unknown");
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
