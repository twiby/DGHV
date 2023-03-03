use core::ops::{Add,Mul};

use num_traits::Zero;
use num_bigint::{BigInt};
use num_bigint::{ToBigInt, RandBigInt};

use crate::dghv::ETA;
use crate::dghv::SymetricEncryption;

fn key_size() -> BigInt {
	let mut min = 2.to_bigint().unwrap();
	min = min.pow((ETA - 1).try_into().unwrap());
	return min
}

pub fn initial_noise_size() -> BigInt {
	let root = (ETA as f64).sqrt() as usize;
	let mut min = 2.to_bigint().unwrap();
	min = min.pow((root-1).try_into().unwrap());
	return min
}

#[derive(Clone)]
pub struct SymetricallyEncryptedInteger<const N: usize> {
	c: BigInt,
	noise_size: BigInt
}

impl<const N: usize> SymetricallyEncryptedInteger<N> {
	pub fn new(c: BigInt, n: BigInt) -> SymetricallyEncryptedInteger<N> {
		SymetricallyEncryptedInteger{c:c, noise_size:n}
	}

	pub fn cipher(&self) -> BigInt {
		self.c.clone()
	}
	pub fn noise(&self) -> BigInt {
		self.noise_size.clone()
	}

	pub fn encrypt_usize(message: usize, p: &BigInt) -> SymetricallyEncryptedInteger<N> {
		if N < message {
			panic!("Attempt to encrypt a message too big");
		}

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

		return SymetricallyEncryptedInteger::<N>::new(p*q + N*r + m, max_r);
	}

	pub fn decrypt_usize(&self, p: &BigInt) -> usize {
		let mut ret: BigInt = (((&self.c+p/2) % p) - p/2) % N;

		if ret < BigInt::zero() {
			ret += N;
		}

		return TryInto::<usize>::try_into(ret.magnitude()).unwrap();
	}
}

impl<const N: usize> SymetricEncryption for SymetricallyEncryptedInteger<N> {
	type KeyType = BigInt;
	type MessageType = usize;

	fn key_gen() -> BigInt {
		let min = key_size();

		let mut rng = rand::thread_rng();
		let mut b = rng.gen_bigint_range(&BigInt::zero(), &min) + &min;

		if &b % N == BigInt::zero() { b += 1; }

		return b;
	}

	fn encrypt(message: Self::MessageType, p: &Self::KeyType) -> SymetricallyEncryptedInteger<N> {
		if N < message {
			panic!("Attempt to encrypt a message too big");
		}

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

		return SymetricallyEncryptedInteger::<N>::new(p*q + N*r + m, max_r);
	}

	fn decrypt(&self, p: &Self::KeyType) -> usize {
		let mut ret: BigInt = (((&self.c+p/2) % p) - p/2) % N;

		if ret < BigInt::zero() {
			ret += N;
		}

		return TryInto::<usize>::try_into(ret.magnitude()).unwrap();
	}
}

impl<'a, const N: usize> Add<&'a SymetricallyEncryptedInteger<N>> for &'a SymetricallyEncryptedInteger<N> {
	type Output = Option<SymetricallyEncryptedInteger<N>>;

	fn add(self, other: &'a SymetricallyEncryptedInteger<N>) -> Self::Output {
		let noise = &self.noise_size + &other.noise_size;
		if noise > key_size()/(2*N) {
			return None;
		}
		return Some(SymetricallyEncryptedInteger::<N>::new(&self.c + &other.c, noise));
	}
}
impl<'a, const N: usize> Mul<&'a SymetricallyEncryptedInteger<N>> for &'a SymetricallyEncryptedInteger<N> {
	type Output = Option<SymetricallyEncryptedInteger<N>>;

	fn mul(self, other: &'a SymetricallyEncryptedInteger<N>) -> Self::Output {
		let noise = &self.noise_size * &other.noise_size;
		if noise > key_size()/(2*N) {
			return None;
		}
		return Some(SymetricallyEncryptedInteger::<N>::new(&self.c * &other.c, noise));
	}
}