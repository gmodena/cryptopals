extern crate base64;
extern crate hex;
use hex::FromHex;


// CHalenge 01
pub fn hex_to_base64(hex: &str) -> String {
    let decoded = hex::decode(&hex).expect("hex::decode failed");
    return base64::encode(decoded);
}

#[test]
fn test_hex_to_base64() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(hex_to_base64(input), expected);
}
// Challenge 02
pub fn fixed_xor(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    return left.iter().zip(right.iter()).map( |(&l, &r)| l ^ r).collect();
}

#[test]
fn test_fixed_xor() {
    let input_left = Vec::<u8>::from_hex("1c0111001f010100061a024b53535009181c").unwrap();
    let input_right = Vec::<u8>::from_hex("686974207468652062756c6c277320657965").unwrap();
    let expected = Vec::<u8>::from_hex("746865206b696420646f6e277420706c6179").unwrap();

    assert_eq!(fixed_xor(input_left, input_right), expected);
}

// Challenge 03

