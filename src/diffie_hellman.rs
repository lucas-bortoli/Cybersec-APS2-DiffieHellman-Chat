use rand::seq::IndexedRandom;

pub type Modulus = u64; // p
pub type Base = u64; // g

pub type Secret = u64;
pub type Public = u64;

pub type SharedSecret = u64;

const PRIMES: [u64; 168] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
];

fn mod_exp(base: u64, exp: u64, modulo: u64) -> u64 {
    let mut resultado = 1;

    for _ in 0..exp {
        resultado *= base;
        resultado %= modulo;
    }

    return resultado;
}

pub fn rand_prime() -> u64 {
    *PRIMES.choose(&mut rand::rng()).unwrap()
}

///
/// p - modulus
/// g - base
pub fn make_keypair(p: Modulus, g: Base) -> (Public, Secret) {
    let mut secret: Secret;
    let mut public: Public;

    loop {
        secret = *PRIMES.choose(&mut rand::rng()).unwrap();
        public = mod_exp(g, secret, p);

        if secret != public {
            break;
        }

        // por azar, a chave secreta é igual a pública...
        // ...então escolher novos valores
    }

    (public, secret)
}

pub fn compute_shared_secret(p: Modulus, my_secret: Secret, other_public: Public) -> SharedSecret {
    mod_exp(other_public, my_secret, p)
}

//pub fn make_private_key(p: u64, g: u64) -> PrivateKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let p: Modulus = 107;
        let g: Base = 467;
        let a_public: Public = 76;
        let a_secret: Secret = 59;
        let b_public: Public = 37;
        let b_secret: Secret = 827;

        println!("{:?}", make_keypair(p, g));
    }

    #[test]
    fn alice_bob_shared_key() {
        // Alice and Bob publicly agree to use a modulus p = 23 and base g = 5 (which is a primitive root modulo 23)
        let p: Modulus = 23;
        let _g: Base = 5;

        // Alice chooses a secret integer a = 4, then sends Bob a_pub = ga mod p = 4
        let a: Secret = 4;
        let a_pub: Public = 4;

        // Bob chooses a secret integer b = 3, then sends Alice a_pub = gb mod p = 10
        let b: Secret = 3;
        let b_pub: Public = 10;

        assert_eq!(compute_shared_secret(p, a, b_pub), 18); // simulando a Alice resolvendo...
        assert_eq!(compute_shared_secret(p, b, a_pub), 18); // simulando o Bob resolvendo...

        // ambos chegam ao valor compartilhado corretamente
    }
}
