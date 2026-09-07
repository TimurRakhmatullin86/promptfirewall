pub fn composite(
    heuristic_score: f32,
    heuristic_labels: &[String],
    tfidf_score: f32,
    entropy_score: f32,
    _threshold: f32,
) -> (f32, Vec<String>) {
    // Weighted combination: heuristic is most reliable, TF-IDF is probabilistic,
    // entropy is the softest signal
    let weighted_heuristic = heuristic_score * 0.9;
    let weighted_tfidf = tfidf_score * 0.7;
    let weighted_entropy = entropy_score * 0.5;

    let final_score = weighted_heuristic
        .max(weighted_tfidf)
        .max(weighted_entropy);

    // If multiple signals agree, boost confidence
    let agreement_count = [
        heuristic_score > 0.3,
        tfidf_score > 0.3,
        entropy_score > 0.3,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    let boosted = if agreement_count >= 2 {
        (final_score * 1.15).min(1.0)
    } else {
        final_score
    };

    (boosted, heuristic_labels.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_heuristic_signal() {
        let (score, labels) = composite(0.9, &["ignore_previous".into()], 0.0, 0.0, 0.7);
        assert!((score - 0.81).abs() < 0.01);
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn all_signals_agree() {
        let (score, _) = composite(0.8, &["test".into()], 0.5, 0.5, 0.7);
        // 0.8*0.9 = 0.72, boosted by 1.15 = 0.828
        assert!(score > 0.8);
    }

    #[test]
    fn no_signals() {
        let (score, labels) = composite(0.0, &[], 0.0, 0.0, 0.7);
        assert_eq!(score, 0.0);
        assert!(labels.is_empty());
    }

    #[test]
    fn tfidf_only() {
        let (score, _) = composite(0.0, &[], 0.6, 0.0, 0.7);
        assert!((score - 0.42).abs() < 0.01);
    }

    #[test]
    fn score_capped_at_one() {
        let (score, _) = composite(1.0, &["test".into()], 0.9, 0.8, 0.7);
        assert!(score <= 1.0);
    }
}
