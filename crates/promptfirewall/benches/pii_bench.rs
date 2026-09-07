use criterion::{black_box, criterion_group, criterion_main, Criterion};
use promptfirewall::{scan, ScanConfig};

fn bench_pii_short(c: &mut Criterion) {
    let text = "My SSN is 123-45-6789 and my card is 4111111111111111";
    let config = ScanConfig::pii_only();
    c.bench_function("pii_short_60b", |b| {
        b.iter(|| scan(black_box(text), &config))
    });
}

fn bench_pii_medium(c: &mut Criterion) {
    let text = "Hello, this is a normal email about the project. \
                My contact info: SSN 123-45-6789, email: user@corp.com, \
                card: 4111111111111111, IBAN: DE89370400440532013000, \
                phone: +1 555-123-4567, AWS key: AKIAIOSFODNN7EXAMPLE. \
                Please process the payment and send confirmation."
        .repeat(3);
    let config = ScanConfig::pii_only();
    c.bench_function("pii_medium_900b", |b| {
        b.iter(|| scan(black_box(&text), &config))
    });
}

fn bench_pii_large(c: &mut Criterion) {
    let base = "This is a normal paragraph of text discussing project requirements. \
                We need to implement the authentication module and set up CI/CD. ";
    let mut text = base.repeat(50); // ~5KB of benign text
    text.push_str(" My SSN is 123-45-6789 and card 4111111111111111 ");
    text.push_str(&base.repeat(50)); // another ~5KB
    let config = ScanConfig::pii_only();
    c.bench_function("pii_large_10kb", |b| {
        b.iter(|| scan(black_box(&text), &config))
    });
}

fn bench_pii_no_findings(c: &mut Criterion) {
    let text = "This is completely normal text with no PII whatsoever. \
                We discuss architecture, design patterns, and code quality. \
                The project uses Rust for performance-critical components."
        .repeat(10);
    let config = ScanConfig::pii_only();
    c.bench_function("pii_clean_2kb", |b| {
        b.iter(|| scan(black_box(&text), &config))
    });
}

criterion_group!(benches, bench_pii_short, bench_pii_medium, bench_pii_large, bench_pii_no_findings);
criterion_main!(benches);
