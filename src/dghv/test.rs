use num_bigint::ToBigInt;


use crate::dghv::{ETA, key_gen, SymetricallyEncryptedBit};

#[test]
fn key_gen_test() {
	let mut min  = 2.to_bigint().unwrap();
	let mut max  = 2.to_bigint().unwrap();

	min = min.pow((ETA-1).try_into().unwrap());
	max = max.pow((ETA).try_into().unwrap());

	let key = key_gen();

	assert!(&key % 2 == 1.to_bigint().unwrap());
	assert!(key >= min);
	assert!(key < max);
}

#[test]
fn encrypt_test() {
	let p = key_gen();

	let _ = SymetricallyEncryptedBit::encrypt(true, &p);
	let _ = SymetricallyEncryptedBit::encrypt(false, &p);
}

#[test]
fn decrypt_test() {
	let p = key_gen();

	let t = SymetricallyEncryptedBit::encrypt(true, &p).decrypt(&p);
	println!("{:?}", t);
	// assert!(t == true);

	let f = SymetricallyEncryptedBit::encrypt(false, &p).decrypt(&p);
	println!("{:?}", f);
	assert!(f == false);
}

