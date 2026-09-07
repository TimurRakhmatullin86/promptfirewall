pub fn validate(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let checksum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if !i.is_multiple_of(2) {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    checksum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_visa() {
        assert!(validate("4111111111111111"));
    }

    #[test]
    fn valid_mastercard() {
        assert!(validate("5500000000000004"));
    }

    #[test]
    fn valid_amex() {
        assert!(validate("378282246310005"));
    }

    #[test]
    fn valid_with_spaces() {
        assert!(validate("4111 1111 1111 1111"));
    }

    #[test]
    fn valid_with_dashes() {
        assert!(validate("4111-1111-1111-1111"));
    }

    #[test]
    fn invalid_number() {
        assert!(!validate("4111111111111112"));
    }

    #[test]
    fn too_short() {
        assert!(!validate("411111"));
    }
}
