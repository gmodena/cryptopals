extern crate base64;
extern crate hex;
extern crate openssl;

use std::collections::{HashSet, HashMap};
use std::fs;
use hex::FromHex;
use openssl::symm::decrypt;
use openssl::symm::Cipher;

// Challenge 01 -- https://cryptopals.com/sets/1/challenges/1
pub fn hex_to_base64(hex: &str) -> String {
    let decoded = hex::decode(&hex).expect("hex::decode failed");
    return base64::encode(decoded);
}

// Challenge 02 -- https://cryptopals.com/sets/1/challenges/2
pub fn fixed_xor(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    return left.iter()
            .zip(right.iter())
            .map( |(&l, &r)| l ^ r)
            .collect()
}

// Challenge 03 - https://cryptopals.com/sets/1/challenges/3
fn score_letter_frequency(text: &[u8]) -> f64 {
    // From https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
    // Note that value sums up to 120%. I added ' ' a posteriori 
    // and did not re-normalize the histogram.
    let en_freq = HashMap::from([
                                (' ', 20.0), // https://www.researchgate.net/figure/Probability-of-characters-in-English-The-SPACE-character-represented-by-has-the_fig2_47518347
                                ('e', 12.02),
                                ('t', 9.10),
                                ('a', 8.12),
                                ('o', 7.68),
                                ('i', 7.31),
                                ('n', 6.95),
                                ('s', 6.28),
                                ('r', 6.02),
                                ('h', 5.92),
                                ('d', 4.32),
                                ('l', 3.98),
                                ('u', 2.88),
                                ('c', 2.71),
                                ('m', 2.61),
                                ('f', 2.30),
                                ('y', 2.11),
                                ('w', 2.09),
                                ('g', 2.03),
                                ('p', 1.82),
                                ('b', 1.49),
                                ('v', 1.11),
                                ('k', 0.69),
                                ('x', 0.17),
                                ('q', 0.11),
                                ('j', 0.10),
                                ('z', 0.07)]);  
    let mut frequency: f64 = 0.0;
    for byte in text.iter() {
        frequency += en_freq.get(&(byte.to_ascii_lowercase() as char)).unwrap_or(&0.0);
    };

    return frequency;
}

fn xor1(text: &[u8], ch: u8) -> Vec<u8> {
    return text.iter().map(|t| t ^ ch).collect()
}

pub struct CandidateKey {
    key: u8,
    text: String,
    score: f64
}

pub fn find_single_xor_key(text: &[u8]) -> CandidateKey {
    let mut max_score = 0.0;
    let mut decrypted = String::new();
    let mut candidate_key = 0;
    for key in 0..255 {
        let candidate = xor1(text, key);
        let score = score_letter_frequency(&candidate);
        if score > max_score {
            candidate_key = key;
            max_score = score;
            decrypted = String::from_utf8_lossy(&candidate).into_owned();
        }
    }
    return CandidateKey { key: candidate_key, text: decrypted, score: max_score };

}

// Challenge 4 -- https://cryptopals.com/sets/1/challenges/4
fn detect_single_character_xor(text: String) -> String {
    let mut max_score = 0.0;
    let mut decrypted = String::new();

    for candidate in text.split("\n") {
        let encoded = Vec::<u8>::from_hex(candidate).unwrap();
        let decoded = find_single_xor_key(&encoded);

        if decoded.score > max_score {
            max_score = decoded.score;
            decrypted = decoded.text;
        }
    }
    return decrypted;
}

// Challenge 5 -- https://cryptopals.com/sets/1/challenges/5
fn repeating_key_xor(text: &str, key: &str) -> Vec<u8> {
    return text.bytes()
            .zip(key.bytes().cycle())
            .map( |(l, r)| l ^ r)
            .collect();
}

// Challenge 6 -- https://cryptopals.com/sets/1/challenges/6
fn hamming_distance(s1: &[u8], s2: &[u8]) -> u32 {
    return s1.iter()
        .zip(s2.iter())
        .map(|(l, r)| (l ^ r).count_ones() as u32)
        .sum()
}

fn find_distance(data: Vec<u8>, keysize: usize, n_samples: usize) -> f32 {
    // TODO(gmodena): shouldn't I normalize distance to account for key lenght?
    let mut distance = 0.0f32;
    let chunks: Vec<&[u8]> = data.chunks(keysize).take(n_samples).collect();
    for i in 0..n_samples {
        for j in i..n_samples {
            distance += hamming_distance(chunks[i], chunks[j]) as f32; 
        }
    }
    return distance; 
}

pub fn base64_to_hex(input: &str) -> Vec<u8> {
    let decoded = base64::decode(input);
    let res = decoded.expect("Shit happened");
    return res;
}

fn find_probable_keysize(data: Vec<u8>) -> usize {
    let mut min_distance = f32::MAX;
    let mut probable_keysize: usize = 0;
    for keysize in 2..40 {
        let distance = find_distance(data.clone(), keysize, 4) / keysize as f32;
        if distance < min_distance {
            min_distance = distance;
            probable_keysize = keysize;
        }
    }
    return probable_keysize;
}

fn transpose_blocks(data: Vec<u8>, keysize: usize) -> Vec<Vec<u8>> {
    let chunks = data.chunks(keysize);
    // TODO(gmodena): meh. Can I this more idiomatic?
    let mut transposed: Vec<Vec<u8>> = vec![vec![]; keysize];

    for chunk in chunks.into_iter() {
        for i in 0..chunk.len() {
            transposed[i].push(chunk[i]);  
        }
    }

    return transposed;
}

fn break_repeating_key_xor(data: Vec<u8>) -> Vec<u8> {
    let probable_keysize = find_probable_keysize(data.clone());
    let blocks = transpose_blocks(data.clone(), probable_keysize);

    let mut key: Vec<u8> = Vec::new();
    for block in blocks {
        let decrypted =  find_single_xor_key(&block); 
        key.push(decrypted.key);
    }
    return key;
}

// Challenge 7 -- https://cryptopals.com/sets/1/challenges/7
fn aes_in_ecb_mode(key: &[u8], ciphertext: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(cipher, key, None, &ciphertext);
    return plaintext.expect("Shit happened");
}

// Challenge 8 -- https://cryptopals.com/sets/1/challenges/8 
fn detect_aes_in_ecb_mode(ciphertext: Vec<u8>) -> bool {
    let mut cache: HashSet<&[u8]> = HashSet::new();
    for block in ciphertext.chunks(16) {
        if cache.contains(block) {
            return true;
        }
        cache.insert(block);
    }
    return false;
}

/// Tests
// Challenge 01 -- https://cryptopals.com/sets/1/challenges/1
#[test]
fn test_hex_to_base64() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(expected, hex_to_base64(input));
}

// Challenge 02 -- https://cryptopals.com/sets/1/challenges/2
#[test]
fn test_fixed_xor() {
    let input_left = Vec::<u8>::from_hex("1c0111001f010100061a024b53535009181c").unwrap();
    let input_right = Vec::<u8>::from_hex("686974207468652062756c6c277320657965").unwrap();
    let expected = Vec::<u8>::from_hex("746865206b696420646f6e277420706c6179").unwrap();

    assert_eq!(expected, fixed_xor(input_left, input_right));
}

// Challenge 03 -- https://cryptopals.com/sets/1/challenges/3
#[test]
fn test_find_single_xor_key() {
    let encoded = Vec::<u8>::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
    let expected = "Cooking MC's like a pound of bacon";
    assert_eq!(expected, find_single_xor_key(&encoded).text);
}

// Challenge 04 -- https://cryptopals.com/sets/1/challenges/4
#[test]
fn test_detect_single_character_xor() {
    let path = "data/set01/4.txt";
    let text = fs::read_to_string(path).expect("Shit happened");
    assert_eq!("Now that the party is jumping\n", detect_single_character_xor(text));
}

// Challenge 05 -- https://cryptopals.com/sets/1/challenges/5
#[test]
fn test_implement_repeating_key_xor() {
    let key = "ICE";
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(expected,
        hex::encode(repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", key)));
}

// Challenge 06 -- https://cryptopals.com/sets/1/challenges/6
#[test]
fn test_base64_to_hex() {
    let input = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let expected = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
 
    assert_eq!(expected, hex::encode(base64_to_hex(input)));
}

#[test]
fn test_hamming_distrance() {
    let expected = 37;
    assert_eq!(expected, hamming_distance(b"this is a test", b"wokka wokka!!!"));
}

#[test]
fn test_break_repeating_key_xor() {
    let path = "data/set01/6.txt";
    let text = fs::read_to_string(path).expect("Shit happened");
    let data = base64_to_hex(&text.replace("\n", ""));

    assert_eq!("Terminator X: Bring the noise", String::from_utf8_lossy(&break_repeating_key_xor(data)));
}

// Challenge 07 -- https://cryptopals.com/sets/1/challenges/7
#[test]
fn test_aes_in_ecb_mode() {
    let path = "data/set01/7.txt";
    let text = fs::read_to_string(path).expect("Shit happened");
    let data = base64_to_hex(&text.replace("\n", ""));
    let key: &[u8; 16] = b"YELLOW SUBMARINE";
    let expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    assert_eq!(expected, String::from_utf8_lossy(&aes_in_ecb_mode(key, data)));
}

// Challenge 08 -- https://cryptopals.com/sets/1/challenges/8
#[test]
fn test_detect_aes_in_ecb_mode() {
    let path = "data/set01/8.txt";
    let text = fs::read_to_string(path).expect("Shit happened");
    let expected: &'static str = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";

    let ciphertext = text.split("\n")
        .filter(|ciphertext| 
            detect_aes_in_ecb_mode(base64_to_hex(&ciphertext)))
        .collect::<Vec<_>>();
    assert_eq!(1, ciphertext.len());
    assert_eq!(expected, ciphertext[0]);
}

