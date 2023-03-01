use core::ops::{Add,Mul};

use num_traits::Zero;
use num_bigint::{BigInt};
use num_bigint::{ToBigInt, RandBigInt};

#[cfg(test)]
mod test;

const LAMBDA: usize = 42;
const RHO: usize = 27;
const ETA: usize = 1026;
const GAMMA: usize = 150000;

fn key_size() -> BigInt {
	let mut min = 2.to_bigint().unwrap();
	min = min.pow((ETA - 1).try_into().unwrap());
	return min
}

fn noise_size() -> BigInt {
	let root = (ETA as f64).sqrt() as usize;
	let mut min = 2.to_bigint().unwrap();
	min = min.pow((root-1).try_into().unwrap());
	return min
}

fn key_gen() -> BigInt {
	let min = key_size();

	let mut rng = rand::thread_rng();
	let mut b = rng.gen_bigint_range(&BigInt::zero(), &min) + min;

	if &b % 2 == BigInt::zero() { b += 1; }

	return b;
}

struct SymetricallyEncryptedBit {
	c: BigInt,
	noise_size: BigInt
}

impl SymetricallyEncryptedBit {
	fn new(c: BigInt, n: BigInt) -> SymetricallyEncryptedBit {
		SymetricallyEncryptedBit{c:c, noise_size:n}
	}

	fn encrypt(message: bool, p: &BigInt) -> SymetricallyEncryptedBit {
		let bit = match message {
			true => 1.to_bigint().unwrap(),
			false => BigInt::zero()
		};

		// r is between -p/4 and p/4
		let min_r = -noise_size();
		let max_r = noise_size();
		let mut rng = rand::thread_rng();
		let r = rng.gen_bigint_range(&min_r, &max_r);

		// q is of the order of 2^(ETA^3)
		let mut min_q = 2.to_bigint().unwrap();
		min_q = min_q.pow((ETA - 1).try_into().unwrap());
		let q = &min_q + rng.gen_bigint_range(&BigInt::zero(), &min_q);

		return SymetricallyEncryptedBit::new(p*q + 2*r + bit, max_r);
	}

	fn decrypt(&self, p: &BigInt) -> bool {
		let ret = (((&self.c+p/2) % p) - p/2) % 2;

		if ret == BigInt::zero() {
			return false;
		} else if ret == 1.to_bigint().unwrap() {
			return true;
		} else if ret == -1.to_bigint().unwrap() {
			return true;
		} else {
			panic!("Bit decrypt: mod 2 didn't work");
		}
	}
}

impl<'a> Add<&'a SymetricallyEncryptedBit> for &'a SymetricallyEncryptedBit {
	type Output = Option<SymetricallyEncryptedBit>;

	fn add(self, other: &'a SymetricallyEncryptedBit) -> Self::Output {
		let noise = &self.noise_size + &other.noise_size;
		if noise > key_size()/2 {
			return None;
		}
		return Some(SymetricallyEncryptedBit::new(&self.c + &other.c, noise));
	}
}
// impl<'a> Mul<&'a SymetricallyEncryptedBit>for &'a SymetricallyEncryptedBit {
// 	type Output = SymetricallyEncryptedBit;

// 	fn mul(self, other: &'a SymetricallyEncryptedBit) -> Self::Output {
// 		return SymetricallyEncryptedBit::new(&self.c * &other.c)
// 	}
// }


