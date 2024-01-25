fn main() {
    // Driver code here.
}

pub fn kid_rsa_keygen(a: u32, b: u32, a_prime: u32, b_prime: u32) -> ((u32, u32), (u32, u32)) {
    let m = a * b - 1;
    let e = a_prime * m + a;
    let d = b_prime * m + b;
    let n = (e as u64 * d as u64 - 1) / m as u64;

    // Pub, Sec.
    ((n.try_into().unwrap(), e), (n.try_into().unwrap(), d))
}

fn encode(text: &str) -> Vec<u32> {
    text.to_owned().chars().map(|c| c as u32).collect()
}

fn decode(text: Vec<u32>) -> Vec<char> {
    text.into_iter()
        .map(|c| char::from_u32(c).expect("Invalid UTF-8"))
        .collect()
}

fn kid_rsa_encrypt(key: (u32, u32), text: Vec<char>) -> Vec<u32> {
    text.into_iter()
        .map(|c| (c as u32 * key.1) % key.0)
        .collect()
}

fn kid_rsa_decrypt(key: (u32, u32), text: Vec<u32>) -> Vec<char> {
    text.into_iter()
        .map(|c| {
            char::from_u32(
                ((c as u64 * key.1 as u64) % key.0 as u64)
                    .try_into()
                    .unwrap(),
            )
            .expect("Invalid UTF-8")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_decrypt() {
        let ((n, e), (_, d)) = kid_rsa_keygen(4, 81, 123, 19963);
        let message = vec![
            2900509, 4609028, 1549587, 4569295, 1271456, 3854101, 1271456, 3973300, 3854101,
            4370630, 4092499, 4013033, 4529562, 4410363, 4648761, 4569295, 1271456, 3893834,
            4648761, 4569295, 4171965, 4370630, 4013033, 4569295, 4569295, 1748252, 1271456,
            2781310, 4529562, 4410363, 3973300, 4410363, 1748252, 1271456, 4092499, 4410363,
            4171965, 4370630, 4092499, 1271456, 4410363, 4648761, 4609028, 1271456, 4807693,
            4410363, 4648761, 4529562, 1271456, 3973300, 4410363, 4410363, 4529562, 1827718,
        ];
        let mut plaintext = kid_rsa_decrypt((n, d), message);
        let text: String = plaintext.into_iter().collect();

        assert_eq!(
            "It's a dangerous business, Frodo, going out your door.",
            &text
        );
    }

    #[test]
    fn test_encrypt() {
        let ((n, e), (_, d)) = kid_rsa_keygen(4, 81, 123, 19963);
        let message = vec![
            2900509, 4609028, 1549587, 4569295, 1271456, 3854101, 1271456, 3973300, 3854101,
            4370630, 4092499, 4013033, 4529562, 4410363, 4648761, 4569295, 1271456, 3893834,
            4648761, 4569295, 4171965, 4370630, 4013033, 4569295, 4569295, 1748252, 1271456,
            2781310, 4529562, 4410363, 3973300, 4410363, 1748252, 1271456, 4092499, 4410363,
            4171965, 4370630, 4092499, 1271456, 4410363, 4648761, 4609028, 1271456, 4807693,
            4410363, 4648761, 4529562, 1271456, 3973300, 4410363, 4410363, 4529562, 1827718,
        ];
        let plaintext = String::from("It's a dangerous business, Frodo, going out your door.");
        let mut ciphertext = kid_rsa_encrypt((n, e), plaintext.chars().collect());

        assert_eq!(message, ciphertext);
    }
}
