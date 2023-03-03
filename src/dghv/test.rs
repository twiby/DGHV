use num_bigint::ToBigInt;

use crate::dghv::{SymetricEncryption, AsymetricEncryption, SymetricallyEncryptedInteger, AsymetricallyEncryptedInteger};
use crate::dghv::{ETA};

type SymetricallyEncryptedBit = SymetricallyEncryptedInteger<2>;
type SymetricallyEncryptedByte = SymetricallyEncryptedInteger<256>;
type AsymetricallyEncryptedBit<const N: usize> = AsymetricallyEncryptedInteger<N, 2>;
type AsymetricallyEncryptedByte<const N: usize> = AsymetricallyEncryptedInteger<N, 256>;

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
fn key_gen_byte_test() {
	let mut min  = 2.to_bigint().unwrap();
	let mut max  = 2.to_bigint().unwrap();

	min = min.pow((ETA-1).try_into().unwrap());
	max = max.pow((ETA).try_into().unwrap());

	let key = SymetricallyEncryptedByte::key_gen();

	assert!(&key % 256 != 0.to_bigint().unwrap());
	assert!(key >= min);
	assert!(key < max);
}

#[test]
fn key_gen_usize_test() {
	let mut min  = 2.to_bigint().unwrap();
	let mut max  = 2.to_bigint().unwrap();

	min = min.pow((ETA-1).try_into().unwrap());
	max = max.pow((ETA).try_into().unwrap());

	let key = SymetricallyEncryptedInteger::<1024>::key_gen();

	assert!(&key % 1024 != 0.to_bigint().unwrap());
	assert!(key >= min);
	assert!(key < max);
}

#[test]
fn encrypt_test() {
	let p = SymetricallyEncryptedBit::key_gen();

	let _ = SymetricallyEncryptedBit::encrypt(1, &p);
	let _ = SymetricallyEncryptedBit::encrypt(0, &p);
}

#[test]
fn decrypt_test() {
	let p = SymetricallyEncryptedBit::key_gen();

	let t = SymetricallyEncryptedBit::encrypt(1, &p).decrypt(&p);
	assert!(t == 1);

	let f = SymetricallyEncryptedBit::encrypt(0, &p).decrypt(&p);
	assert!(f == 0);
}

#[test]
fn asymetric_decrypt_test() {
	let (pk, sk) = AsymetricallyEncryptedBit::<10>::key_gen();

	let t = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk).decrypt(&sk);
	assert!(t == 1);

	let f = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk).decrypt(&sk);
	assert!(f == 0);
}

#[test]
fn byte_decrypt_test() {
	let p = SymetricallyEncryptedByte::key_gen();

	for n in 0..=255 {
		let m = SymetricallyEncryptedByte::encrypt(n, &p).decrypt(&p);
		assert_eq!(n, m);
	}
}

#[test]
fn integer_decrypt_test() {
	let p = SymetricallyEncryptedInteger::<1024>::key_gen();

	for n in 500..1000 {
		let m = SymetricallyEncryptedInteger::<1024>::encrypt(n, &p).decrypt(&p);
		assert_eq!(n, m);
	}
}

#[test]
fn asym_byte_decrypt_test() {
	let (pk, sk) = AsymetricallyEncryptedByte::<256>::key_gen();

	for n in 0..=255 {
		let m = AsymetricallyEncryptedByte::encrypt(n, &pk).decrypt(&sk);
		assert_eq!(n, m);
	}
}

#[test]
fn asym_usize_decrypt_test() {
	let (pk, sk) = AsymetricallyEncryptedInteger::<256, 1024>::key_gen();

	for n in 950..1024 {
		let m = AsymetricallyEncryptedInteger::encrypt(n, &pk).decrypt(&sk);
		assert_eq!(n, m);
	}
}

#[test]
fn addition() {
	let p = SymetricallyEncryptedBit::key_gen();

	let mut c1 = SymetricallyEncryptedBit::encrypt(0, &p);
	let mut c2 = SymetricallyEncryptedBit::encrypt(0, &p);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&p), 0);

	c1 = SymetricallyEncryptedBit::encrypt(1, &p);
	c2 = SymetricallyEncryptedBit::encrypt(0, &p);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&p), 1);

	c1 = SymetricallyEncryptedBit::encrypt(0, &p);
	c2 = SymetricallyEncryptedBit::encrypt(1, &p);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&p), 1);

	c1 = SymetricallyEncryptedBit::encrypt(1, &p);
	c2 = SymetricallyEncryptedBit::encrypt(1, &p);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&p), 0);
}

#[test]
fn mutiplication() {
	let p = SymetricallyEncryptedBit::key_gen();

	let mut c1 = SymetricallyEncryptedBit::encrypt(0, &p);
	let mut c2 = SymetricallyEncryptedBit::encrypt(0, &p);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&p), 0);

	c1 = SymetricallyEncryptedBit::encrypt(1, &p);
	c2 = SymetricallyEncryptedBit::encrypt(0, &p);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&p), 0);

	c1 = SymetricallyEncryptedBit::encrypt(0, &p);
	c2 = SymetricallyEncryptedBit::encrypt(1, &p);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&p), 0);

	c1 = SymetricallyEncryptedBit::encrypt(1, &p);
	c2 = SymetricallyEncryptedBit::encrypt(1, &p);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&p), 1);
}

#[test]
fn asymetric_addition() {
	let (pk, sk) = AsymetricallyEncryptedBit::<10>::key_gen();

	let mut c1 = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk);
	let mut c2 = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), 0);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), 1);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), 1);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk);
	assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), 0);
}

#[test]
fn asymetric_mutiplication() {
	let (pk, sk) = AsymetricallyEncryptedBit::<10>::key_gen();

	let mut c1 = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk);
	let mut c2 = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), 0);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), 0);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(0, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), 0);

	c1 = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk);
	c2 = AsymetricallyEncryptedBit::<10>::encrypt(1, &pk);
	assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), 1);
}

#[test]
fn byte_addition_multiplication() {
	let p = SymetricallyEncryptedByte::key_gen();

	for n in 100..150 {
		for m in 0..50 {
			let c1 = SymetricallyEncryptedByte::encrypt(n, &p);
			let c2 = SymetricallyEncryptedByte::encrypt(m, &p);

			assert_eq!((&c1 + &c2).unwrap().decrypt(&p), n+m);
		}
	}

	for n in 0..=16 {
		for m in 0..16 {
			let c1 = SymetricallyEncryptedByte::encrypt(n, &p);
			let c2 = SymetricallyEncryptedByte::encrypt(m, &p);

			assert_eq!((&c1 * &c2).unwrap().decrypt(&p), n*m);
		}
	}
}

#[test]
fn integer_addition_multiplication() {
	let p = SymetricallyEncryptedInteger::<1024>::key_gen();

	for n in 900..950 {
		for m in 0..50 {
			let c1 = SymetricallyEncryptedInteger::<1024>::encrypt(n, &p);
			let c2 = SymetricallyEncryptedInteger::<1024>::encrypt(m, &p);

			assert_eq!((&c1 + &c2).unwrap().decrypt(&p), n+m);
		}
	}

	for n in 0..=32 {
		for m in 0..32 {
			let c1 = SymetricallyEncryptedInteger::<1024>::encrypt(n, &p);
			let c2 = SymetricallyEncryptedInteger::<1024>::encrypt(m, &p);

			assert_eq!((&c1 * &c2).unwrap().decrypt(&p), n*m);
		}
	}
}

#[test]
fn asym_byte_addition_multiplication() {
	let (pk, sk) = AsymetricallyEncryptedByte::<10>::key_gen();

	for n in 100..150 {
		for m in 0..50 {
			let c1 = AsymetricallyEncryptedByte::encrypt(n, &pk);
			let c2 = AsymetricallyEncryptedByte::encrypt(m, &pk);

			assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), n+m);
		}
	}

	for n in 0..=16 {
		for m in 0..16 {
			let c1 = AsymetricallyEncryptedByte::encrypt(n, &pk);
			let c2 = AsymetricallyEncryptedByte::encrypt(m, &pk);

			assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), n*m);
		}
	}
}

#[test]
fn asym_usize_addition_multiplication() {
	let (pk, sk) = AsymetricallyEncryptedInteger::<10, 1024>::key_gen();

	for n in 900..950 {
		for m in 0..50 {
			let c1 = AsymetricallyEncryptedInteger::encrypt(n, &pk);
			let c2 = AsymetricallyEncryptedInteger::encrypt(m, &pk);

			assert_eq!((&c1 + &c2).unwrap().decrypt(&sk), n+m);
		}
	}

	for n in 0..16 {
		for m in 0..16 {
			let c1 = AsymetricallyEncryptedInteger::encrypt(n, &pk);
			let c2 = AsymetricallyEncryptedInteger::encrypt(m, &pk);

			assert_eq!((&c1 * &c2).unwrap().decrypt(&sk), n*m);
		}
	}
}

#[test]
#[should_panic]
fn noise_blowup() {
	let p = SymetricallyEncryptedBit::key_gen();

	let mut c1 = SymetricallyEncryptedBit::encrypt(1, &p);
	let mut c2 = SymetricallyEncryptedBit::encrypt(1, &p);

	while let Some(c) = &c1 * &c2 {
		c1 = c.clone();
		c2 = c.clone();
	}

	let none = &c1 * &c2;
	assert_eq!(none.unwrap().decrypt(&p), 1);
}

