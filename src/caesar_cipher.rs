pub struct Caesar {}

impl Caesar {
    fn process(key: i8, text: &str, encrypt: bool) -> String {
        let mut out = String::with_capacity(text.len());
        let shift = if encrypt { key } else { -key };

        for ch in text.chars() {
            if ch.is_ascii_alphabetic() {
                let a: u8 = if ch.is_ascii_uppercase() { b'A' } else { b'a' };
                let alpha_index = (ch as u8 - a) as i8;
                let shifted = (alpha_index + shift + 26) % 26; // +26 para evitar negativo
                out.push((a + shifted as u8) as char);
            } else {
                out.push(ch);
            }
        }
        out
    }

    pub fn encrypt(key: i8, plaintext: &String) -> String {
        Caesar::process(key, plaintext, true)
    }

    pub fn decrypt(key: i8, ciphertext: &String) -> String {
        Caesar::process(key, ciphertext, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_example() {
        let cipher = Caesar::encrypt(3, &"EVIDENCIAS fff".to_string());
        assert_eq!(cipher, "HYLGHQFLDV iii");
        let plain = Caesar::decrypt(3, &cipher);
        assert_eq!(plain, "EVIDENCIAS fff");
    }
}
