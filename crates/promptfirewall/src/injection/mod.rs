mod heuristic;
mod tfidf;
mod entropy;
mod score;

pub fn scan_injection(text: &str, threshold: f32) -> (f32, Vec<String>) {
    let (heuristic_score, heuristic_labels) = heuristic::detect(text);
    let tfidf_score = tfidf::classify(text);
    let entropy_score = entropy::analyze(text);

    let (final_score, mut labels) = score::composite(
        heuristic_score,
        &heuristic_labels,
        tfidf_score,
        entropy_score,
        threshold,
    );

    if final_score >= threshold {
        if tfidf_score > 0.5 && !labels.contains(&"tfidf_suspicious".to_string()) {
            labels.push("tfidf_suspicious".to_string());
        }
        if entropy_score > 0.6 && !labels.contains(&"high_entropy_payload".to_string()) {
            labels.push("high_entropy_payload".to_string());
        }
    }

    (final_score, labels)
}
