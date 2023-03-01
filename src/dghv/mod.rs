use num_traits::Zero;
use num_bigint::{BigInt};
use num_bigint::{ToBigInt, RandBigInt};

#[cfg(test)]
mod test;

const LAMBDA: usize = 42;
const RHO: usize = 27;
const ETA: usize = 1026;
const GAMMA: usize = 150000;

fn key_gen() -> BigInt {
	let mut rng = rand::thread_rng();

	let mut min = 2.to_bigint().unwrap();
	min = min.pow((ETA - 1).try_into().unwrap());

	let mut b = rng.gen_bigint_range(&BigInt::zero(), &min) + min;

	if &b % 2 == BigInt::zero() { b += 1; }

	return b;
}

struct SymetricallyEncryptedBit {
	c: BigInt
}

impl SymetricallyEncryptedBit {
	fn new(c: BigInt) -> SymetricallyEncryptedBit {
		SymetricallyEncryptedBit{c:c}
	}

	fn encrypt(message: bool, p: &BigInt) -> SymetricallyEncryptedBit {
		let bit = match message {
			true => 1.to_bigint().unwrap(),
			false => BigInt::zero()
		};

		// r is between -p/4 and p/4
		let min_r = -p/4;
		let max_r = p/4;
		let mut rng = rand::thread_rng();
		let r = rng.gen_bigint_range(&min_r, &max_r);

		// q is of the order of 2^(ETA^3)
		let mut min_q = 2.to_bigint().unwrap();
		min_q = min_q.pow((ETA - 1).try_into().unwrap());
		let q = &min_q + rng.gen_bigint_range(&BigInt::zero(), &min_q);

		dbg!((2*&r + &bit) + p);
		return SymetricallyEncryptedBit::new(dbg!(dbg!(p*q) + dbg!(2*r + bit)));
	}

	fn decrypt(&self, p: &BigInt) -> bool {
		let ret = (((&self.c+p/2) % p) - p/2) % 2;

		if ret == BigInt::zero() {
			return false;
		} else if ret == 1.to_bigint().unwrap() {
			return true;
		}else if ret == -1.to_bigint().unwrap() {
			return true;
		} else {
			panic!("Bit decrypt: mod 2 didn't work");
		}
	}
}


