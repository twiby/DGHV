use num_bigint::ToBigInt;

use crate::dghv::{SymetricEncryption, AsymetricEncryption};
use crate::dghv::{ETA, SymetricallyEncryptedBit, AsymetricallyEncryptedBit};

#[test]
fn key_gen_test() {
	let mut min  = 2.to_bigint().unwrap();
	let mut max  = 2.to_bigint().unwrap();

	min = min.pow((ETA-1).try_into().unwrap());
	max = max.pow((ETA).try_into().unwrap());

	let key = SymetricallyEncryptedBit::key_gen();

	assert!(&key % 2 == 1.to_bigint().unwrap());
	assert!(key >= min);
	assert!(key < max);
}

#[test]
fn encrypt_test() {
	let p = SymetricallyEncryptedBit::key_gen();

	let _ = SymetricallyEncryptedBit::encrypt(true, &p);
	let _ = SymetricallyEncryptedBit::encrypt(false, &p);
}

#[test]
fn decrypt_test() {
	let p = SymetricallyEncryptedBit::key_gen();

	let t = SymetricallyEncryptedBit::encrypt(true, &p).decrypt(&p);
	assert!(t == true);

	let f = SymetricallyEncryptedBit::encrypt(false, &p).decrypt(&p);
	assert!(f == false);
}

#[test]
fn asymetric_decrypt_test() {
	let (pk, sk) = AsymetricallyEncryptedBit::<10>::key_gen();

	let t = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk).decrypt(&sk);
	assert!(t == true);

	let f = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk).decrypt(&sk);
	assert!(f == false);
}

#[test]
fn addition() {
	let p = SymetricallyEncryptedBit::key_gen();

	let mut c1 = SymetricallyEncryptedBit::encrypt(false, &p);
	let mut c2 = SymetricallyEncryptedBit::encrypt(false, &p);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&p), false);

	c1 = SymetricallyEncryptedBit::encrypt(true, &p);
	c2 = SymetricallyEncryptedBit::encrypt(false, &p);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&p), true);

	c1 = SymetricallyEncryptedBit::encrypt(false, &p);
	c2 = SymetricallyEncryptedBit::encrypt(true, &p);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&p), true);

	c1 = SymetricallyEncryptedBit::encrypt(true, &p);
	c2 = SymetricallyEncryptedBit::encrypt(true, &p);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&p), false);
}

#[test]
fn mutiplication() {
	let p = SymetricallyEncryptedBit::key_gen();

	let mut c1 = SymetricallyEncryptedBit::encrypt(false, &p);
	let mut c2 = SymetricallyEncryptedBit::encrypt(false, &p);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&p), false);

	c1 = SymetricallyEncryptedBit::encrypt(true, &p);
	c2 = SymetricallyEncryptedBit::encrypt(false, &p);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&p), false);

	c1 = SymetricallyEncryptedBit::encrypt(false, &p);
	c2 = SymetricallyEncryptedBit::encrypt(true, &p);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&p), false);

	c1 = SymetricallyEncryptedBit::encrypt(true, &p);
	c2 = SymetricallyEncryptedBit::encrypt(true, &p);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&p), true);
}

#[test]
fn asymetric_addition() {
	let (pk, sk) = AsymetricallyEncryptedBit::<10>::key_gen();

	let mut c1 = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk);
	let mut c2 = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), false);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), true);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), true);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), false);
}

#[test]
fn asymetric_mutiplication() {
	let (pk, sk) = AsymetricallyEncryptedBit::<10>::key_gen();

	let mut c1 = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk);
	let mut c2 = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), false);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), false);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(false, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), false);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(true, &pk);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), true);
}

