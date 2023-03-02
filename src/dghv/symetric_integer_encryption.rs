use core::ops::{Add,Mul};

use num_traits::Zero;
use num_bigint::{BigInt};
use num_bigint::{ToBigInt, RandBigInt};

use crate::dghv::ETA;
use crate::dghv::SymetricEncryption;
use crate::dghv::symetric_bit_encryption::initial_noise_size;

fn key_size() -> BigInt {
	let mut min = 2.to_bigint().unwrap();
	min = min.pow((ETA - 1).try_into().unwrap());
	return min
}

#[derive(Clone)]
pub struct SymetricallyEncryptedByte {
	c: BigInt,
	noise_size: BigInt
}

impl SymetricallyEncryptedByte {
	pub fn new(c: BigInt, n: BigInt) -> SymetricallyEncryptedByte {
		SymetricallyEncryptedByte{c:c, noise_size:n}
	}

	pub fn cipher(&self) -> BigInt {
		self.c.clone()
	}
	pub fn noise(&self) -> BigInt {
		self.noise_size.clone()
	}
}

impl SymetricEncryption for SymetricallyEncryptedByte {
	type KeyType = BigInt;
	type MessageType = u8;

	fn key_gen() -> BigInt {
		let min = key_size();

		let mut rng = rand::thread_rng();
		let mut b = rng.gen_bigint_range(&BigInt::zero(), &min) + &min;

		while num_integer::gcd(b.clone(), 256.to_bigint().unwrap()) != 1.to_bigint().unwrap() {
			b = rng.gen_bigint_range(&BigInt::zero(), &min) + &min;
		}

		return b;
	}

	fn encrypt(message: Self::MessageType, p: &Self::KeyType) -> SymetricallyEncryptedByte {
		let m = message.to_bigint().unwrap();

		// r is between -p/4 and p/4
		let min_r = -initial_noise_size();
		let max_r = initial_noise_size();
		let mut rng = rand::thread_rng();
		let r = rng.gen_bigint_range(&min_r, &max_r);

		// q is of the order of 2^(ETA^3)
		let mut min_q = 2.to_bigint().unwrap();
		min_q = min_q.pow(ETA as u32);
		let q = &min_q + rng.gen_bigint_range(&BigInt::zero(), &min_q);

		return SymetricallyEncryptedByte::new(p*q + 256*r + m, max_r);
	}

	fn decrypt(&self, p: &Self::KeyType) -> u8 {
		let mut ret: BigInt = (((&self.c+p/2) % p) - p/2) % 256;

		if ret < BigInt::zero() {
			ret += 256;
		}

		return TryInto::<u8>::try_into(ret.magnitude()).unwrap();
	}
}

impl<'a> Add<&'a SymetricallyEncryptedByte> for &'a SymetricallyEncryptedByte {
	type Output = Option<SymetricallyEncryptedByte>;

	fn add(self, other: &'a SymetricallyEncryptedByte) -> Self::Output {
		let noise = &self.noise_size + &other.noise_size;
		if noise > key_size()/512 {
			return None;
		}
		return Some(SymetricallyEncryptedByte::new(&self.c + &other.c, noise));
	}
}
impl<'a> Mul<&'a SymetricallyEncryptedByte> for &'a SymetricallyEncryptedByte {
	type Output = Option<SymetricallyEncryptedByte>;

	fn mul(self, other: &'a SymetricallyEncryptedByte) -> Self::Output {
		let noise = &self.noise_size * &other.noise_size;
		if noise > key_size()/512 {
			return None;
		}
		return Some(SymetricallyEncryptedByte::new(&self.c * &other.c, noise));
	}
}