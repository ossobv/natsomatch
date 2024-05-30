use criterion::{criterion_group, criterion_main, Criterion};

/*
use async_nats::header::NATS_MESSAGE_ID;

fn test_header_build(provided_id: &str) -> () {
    let mut headers = async_nats::HeaderMap::new();
    headers.insert(NATS_MESSAGE_ID, provided_id);

    let found_id = headers.get(NATS_MESSAGE_ID).unwrap();
    let found_id_str: &str = found_id.as_ref();
    assert_eq!(found_id_str, provided_id)
}

fn test_header_reuse(headers: async_nats::HeaderMap, provided_id: &str) -> () {
    let value_str: &str = headers.get(NATS_MESSAGE_ID).unwrap();
    value_str[0] = 'X';
    //let value_bin: &mut [u8] = value_str.as_bytes();
    //value_bin[0] = b'X';

    let found_id = headers.get(NATS_MESSAGE_ID).unwrap();
    let found_id_str: &str = found_id.as_ref();
    assert_eq!(found_id_str, provided_id)
}
*/

fn criterion_benchmark(_c: &mut Criterion) {
    /*
    let mut reusable_headers = async_nats::HeaderMap::new();
    reusable_headers.append(NATS_MESSAGE_ID, "0123456789abcdef0123456789abcdef");
    c.bench_function("test_header_build", |b| {
        b.iter(|| test_header_build(black_box("testing9876")))
    });
    c.bench_function("test_header_reuse", |b| {
        b.iter(|| test_header_reuse(black_box(reusable_headers), black_box("testing1234")))
    });
    */
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
