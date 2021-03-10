pub mod cipher {
    use rand::{Rng, thread_rng};
    use rand::distributions::Uniform;
    use std::collections::HashMap;
    /// # Ciphers
    /// This crate is implementation of two main traditional ciphers.
    /// ## Shift Cipher
    ///   -  In this cipher, the character are shifted by the key. 
    ///     For example, if key is 15 and original-text is "hello" then
    ///     cipher-text is "wtaad" (i.e. h + 15 = w). It is also known as rot cipher.
    ///     We implemented here the Shift Cipher for English alphabets. It is also
    ///     known as Caesar Cipher on the name of Julius Caesar who used to use it 
    ///     to communicate with his officers.
    /// ## Transpositional Cipher
    ///   -  In this cipher, the symbols in block of symbols are reordered or permutated.
    ///     For example, if key is 2 4 1 3 and original-text is "word" then
    ///     cipher-text is "odwr". If the key is long then it is more effective. Therefore, size
    ///     of the original-text and cipher-text also increases. This cipher is implemented for all
    ///     visible and non-whitespace characters.
    /// - `ShiftCipher` or shift cipher takes the key as data
    ///    and `TransCipher` or Transposition cipher takes the size of key or block
    /// ## Examples
    /// ### Shift Cipher

    /// ```
    ///     use classical_ciphers::cipher::Ciphers;
    ///     //Data
    ///     let manchine = Ciphers::ShiftCipher(15); //creating a cipher key data
    ///     let message = String::from("hello");
    ///     //Running
    ///     let cipher = manchine.clone().encrypt(message); //encrypting the message
    ///     let message = manchine.clone().decrypt(cipher.clone()); //decrypting the message
    ///     //Output
    ///     println!("Message: {:?}", message);
    ///     println!("Key: {:?}", manchine);
    ///     println!("Cipher: {:?}", cipher);
    /// ```

    /// ### Transpositional Cipher

    /// ```
    ///     use classical_ciphers::cipher::Ciphers;
    ///     //Data
    ///     let key = Ciphers::trans_key_gen(3);
    ///     let manchine = Ciphers::TransCipher(key); //creating a cipher key data
    ///     let message = String::from("hello");
    ///     //Running
    ///     let cipher = manchine.clone().encrypt(message); //encrypting the message
    ///     let message = manchine.clone().decrypt(cipher.clone()); //decrypting the message
    ///     //Output
    ///     println!("Message: {:?}", message);
    ///     println!("Key: {:?}", manchine);
    ///     println!("Cipher: {:?}", cipher);
    /// ```
    #[derive(Debug, Clone)]
    pub enum Ciphers {
        ShiftCipher(u8), 
        TransCipher(Vec<usize>), 
    }

    impl Ciphers {
        /// Returns the key or keysize stored in Ciphers
        pub fn key(&self) -> u8 {
            match *self {
                Self::ShiftCipher(ref key) => *key,
                Self::TransCipher(ref key) => key.len() as u8
            }
        }
        /// Encrypts the data
        pub fn encrypt(self, original_text: String) -> String {
            match self {
                Self::ShiftCipher(key) => 
                    Self::shift_encrypt(key % 26, original_text),
                Self::TransCipher(key) => 
                    Self::trans_encrypt(key,original_text)
            }
        }
        /// Decrypts the data
        pub fn decrypt(self, cipher_text: String) -> String {
            match self {
                Self::ShiftCipher(key) =>
                    Self::shift_decrypt(key % 26, cipher_text), 
                Self::TransCipher(key) => 
                    Self::trans_decrypt(key, cipher_text)
            } 
        }

        fn shift_encrypt(key: u8, mut original_text: String) -> String {
            unsafe {
                Self::rot_vec_up(key, original_text.as_mut_vec());
                original_text
            }
        }
        
        fn shift_decrypt(key: u8, mut cipher_text: String) -> String {
            unsafe {
                Self::rot_vec_down(key, cipher_text.as_mut_vec());
                cipher_text
            }
        }

        fn rot_vec_up(key: u8, org: &mut Vec<u8>) {
            for c in org.iter_mut() {
                if (b'A'..=b'Z').contains(c) || (b'a'..=b'z').contains(c) {
                    *c = Self::rot_up(key, *c);
                } else { 
                    continue;
                }
            }
        }

        fn rot_vec_down(key: u8, org: &mut Vec<u8>) {
            for c in org.iter_mut() {
                if (b'A'..=b'Z').contains(c) || (b'a'..=b'z').contains(c) {
                    *c = Self::rot_down(key, *c);
                } else { 
                    continue;
                }
            }
        }

        fn rot_up(key: u8, x: u8) -> u8 {

            let rot_wrap_up = |b: u8| key - (b - x + 1);
            match x {
                x @ b'A'..=b'Z' if key + x > b'Z' => Self::rot_up(rot_wrap_up(b'Z'), b'A'), // For wrap around behaviour
                x @ b'a'..=b'z' if key + x > b'z' => Self::rot_up(rot_wrap_up(b'z'), b'a'), 
                _ => x + key
            }
        }

        fn rot_down(key: u8, x: u8) -> u8 {
            // HELLO => WTAAD
            let rot_wrap_down = |b: u8| key - (x - b + 1);
            match x {
                x @ b'A'..=b'Z' if x - key < b'A' => Self::rot_down(rot_wrap_down(b'A'), b'Z'), // For wrap around behaviour
                x @ b'a'..=b'z' if x - key < b'a' => Self::rot_down(rot_wrap_down(b'a'), b'z'),
                _ => x - key
            }
        }

        fn trans_encrypt(key: Vec<usize>, mut original_text: String) -> String {
            
            unsafe {
                Self::encrypt_trans_vec(key, original_text.as_mut_vec());
                original_text
            }
        }

        fn trans_decrypt(key: Vec<usize>, mut original_text: String) -> String {
            unsafe {
                Self::decrypt_trans_vec(key, original_text.as_mut_vec());
                original_text
            }
        }
        /// Produce a key for Transpositional Cipher.
        pub fn trans_key_gen(key_size: usize) -> Vec<usize> {
            
            let mut rng = thread_rng();
            let mut nrng = (&mut rng).sample_iter(Uniform::new_inclusive(0, key_size-1));
            
            let mut v = Vec::with_capacity(key_size);
            let mut num: HashMap<usize, bool> = HashMap::new();
            
            while v.len() != key_size {
                let x = nrng.next().unwrap();
                num.entry(x).or_insert_with(
                    || {
                        v.push(x);
                        true
                    } 
                );
            }
            
            v
        }

        fn encrypt_trans_vec(key: Vec<usize>, org: &mut Vec<u8>) {
            let mut i = 0;
            let key_size = key.len();
            while i + key_size < org.len() {
            // print!("{} ", quo);
                Self::encrypt_with_accord(&mut org[i..key_size + i], &key);
                i += key_size;
            }
        }

        fn decrypt_trans_vec(key: Vec<usize>, org: &mut Vec<u8>) {
            let mut i = 0;
            let key_size = key.len();
            while i + key_size < org.len() {
            // print!("{} ", quo);
                Self::decrypt_with_accord(&mut org[i..key_size + i], &key);
                i += key_size;
            }
        }

        #[allow(clippy::ptr_arg)]
        fn encrypt_with_accord<T: Copy>(v: &mut [T], acc: &Vec<usize>) {
            let mut num: HashMap<usize, T> = HashMap::new();
            for i in 0..v.len() {
                num.insert(i, v[i]);
                v[i] = match num.contains_key(&(acc[i])) {
                    true    => num.remove(&(acc[i])).unwrap(),
                    false   => v[acc[i]]
                }
            }
        }
        #[allow(clippy::ptr_arg)]
        fn decrypt_with_accord<T: Copy>(v: &mut [T], acc: &Vec<usize>) {
        let mut num: HashMap<usize, T> = HashMap::new();
        for i in 0..v.len() {
            num.insert(acc[acc[i]] as usize, v[acc[i]]);
            v[acc[i]] = match num.contains_key(&(acc[i])) {
                true    => num.remove(&(acc[i])).unwrap(),
                false   => v[i]
            }
        }
    }

    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn shift_cipher_works() {
        use crate::cipher::Ciphers; 
        let key = 15;
        let message = String::from("HelloHowAreYou!");
        let manchine = Ciphers::ShiftCipher(key);
        let cipher = manchine.clone().encrypt(message.clone());
        let result = manchine.decrypt(cipher);
        assert_eq!(result, message);
    }
    #[test]
    fn trans_cipher_works() {
        use crate::cipher::Ciphers; 
        let key_size = 5;
        let key = Ciphers::trans_key_gen(key_size);
        let manchine = Ciphers::TransCipher(key);
        let message = String::from("HelloHowAreYou!");
        let cipher = manchine.clone().encrypt(message.clone());
        let result = manchine.decrypt(cipher);
        assert_eq!(result, message);
    }
}
