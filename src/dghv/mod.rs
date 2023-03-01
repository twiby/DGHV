
use num_traits::Zero;
use num_bigint::{BigInt};
use num_bigint::{ToBigInt, RandBigInt};

#[cfg(test)]
mod test;

const LAMBDA: usize = 42;
const RHO: usize = 27;
const ETA: usize = 1026;
const GAMMA: usize = 150000;

mod symetric_bit_encryption;
pub use symetric_bit_encryption::SymetricallyEncryptedBit;

fn key_size() -> BigInt {
	let mut min = 2.to_bigint().unwrap();
	min = min.pow((ETA - 1).try_into().unwrap());
	return min
}

fn initial_noise_size() -> BigInt {
	let root = (ETA as f64).sqrt() as usize;
	let mut min = 2.to_bigint().unwrap();
	min = min.pow((root-1).try_into().unwrap());
	return min
}

pub fn key_gen() -> BigInt {
	let min = key_size();

	let mut rng = rand::thread_rng();
	let mut b = rng.gen_bigint_range(&BigInt::zero(), &min) + min;

	if &b % 2 == BigInt::zero() { b += 1; }

	return b;
}


