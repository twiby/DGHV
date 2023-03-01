use num_traits::Zero;
use num_bigint::{BigInt, Sign};
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

	let b = rng.gen_bigint_range(&BigInt::zero(), &min);

	return b + min;
}

struct EncryptedBit {
	c: BigInt
}

impl EncryptedBit {
	fn new(c: BigInt) -> EncryptedBit {
		EncryptedBit{c:c}
	}
}
