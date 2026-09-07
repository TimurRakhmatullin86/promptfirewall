pub fn validate_iban(iban: &str) -> bool {
    let cleaned: String = iban.chars().filter(|c| !c.is_whitespace()).collect();

    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }

    let first_two = &cleaned[..2];
    if !first_two.chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }

    let check_digits = &cleaned[2..4];
    if !check_digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // ISO 7064 mod-97-10: move first 4 chars to end, convert letters to numbers
    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[..4]);

    let numeric_str: String = rearranged
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                format!("{}", c as u32 - 'A' as u32 + 10)
            } else {
                c.to_string()
            }
        })
        .collect();

    // mod 97 on a large number — process in chunks
    let remainder = numeric_str
        .chars()
        .fold(0u64, |acc, ch| {
            let digit = ch.to_digit(10).unwrap() as u64;
            (acc * 10 + digit) % 97
        });

    remainder == 1
}

pub fn validate_ssn_area(area: u16) -> bool {
    area != 0 && area != 666 && area < 900
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_german_iban() {
        assert!(validate_iban("DE89370400440532013000"));
    }

    #[test]
    fn valid_uk_iban() {
        assert!(validate_iban("GB29NWBK60161331926819"));
    }

    #[test]
    fn valid_iban_with_spaces() {
        assert!(validate_iban("DE89 3704 0044 0532 0130 00"));
    }

    #[test]
    fn invalid_iban_bad_checksum() {
        assert!(!validate_iban("DE00370400440532013000"));
    }

    #[test]
    fn ssn_area_valid() {
        assert!(validate_ssn_area(123));
        assert!(validate_ssn_area(1));
        assert!(validate_ssn_area(899));
    }

    #[test]
    fn ssn_area_invalid() {
        assert!(!validate_ssn_area(0));
        assert!(!validate_ssn_area(666));
        assert!(!validate_ssn_area(900));
        assert!(!validate_ssn_area(999));
    }
}
