use core::ops::{Add, Mul};

use rand::Rng;
use num_bigint::{BigInt, RandBigInt};

use crate::dghv::{AsymetricEncryption, SymetricEncryption, SymetricallyEncryptedBit};
use crate::dghv::symetric_bit_encryption::initial_noise_size;

pub struct AsymetricallyEncryptedBit<const N: usize> {
	c: SymetricallyEncryptedBit
}

impl<const N: usize> AsymetricallyEncryptedBit<N> {
	fn new(c: SymetricallyEncryptedBit) -> Self {
		Self{c:c}
	}
}

impl<const N: usize> AsymetricEncryption for AsymetricallyEncryptedBit<N> {
	type MessageType = bool;
	type PublicKeyType = [SymetricallyEncryptedBit; N];
	type PrivateKeyType = BigInt;

	fn key_gen() -> (Self::PublicKeyType, Self::PrivateKeyType) {
		let sk = SymetricallyEncryptedBit::key_gen();

		let pk: [SymetricallyEncryptedBit; N] = core::array::from_fn(|_| SymetricallyEncryptedBit::encrypt(false, &sk));

		return (pk, sk);
	}

	fn encrypt(m: bool, p: &Self::PublicKeyType) -> Self {
		let mut rng = rand::thread_rng();

		let mut ret = p[0].cipher();
		for i in 1..N {
			if rng.gen_bool(0.5) {
				ret = ret + &p[i].cipher();
			}
		}

		// r is between -p/4 and p/4
		let min_r = -initial_noise_size();
		let max_r = initial_noise_size();
		let r = rng.gen_bigint_range(&min_r, &max_r);
		ret = &ret + 2*r;

		if m {
			ret += 1;
		}
		return AsymetricallyEncryptedBit::new(SymetricallyEncryptedBit::new(ret, (N+1)*p[0].noise()));
	}

	fn decrypt(&self, sk: &BigInt) -> bool {
		self.c.decrypt(sk)
	}
}

impl<'a, const N: usize> Add<&'a AsymetricallyEncryptedBit<N>> for &'a AsymetricallyEncryptedBit<N> {
	type Output = Option<AsymetricallyEncryptedBit<N>>;

	fn add(self, other: &'a AsymetricallyEncryptedBit<N>) -> Self::Output {
		match &self.c + &other.c {
			None => None,
			Some(c) => Some(AsymetricallyEncryptedBit::<N>::new(c))
		}
	}
}
impl<'a, const N: usize> Mul<&'a AsymetricallyEncryptedBit<N>> for &'a AsymetricallyEncryptedBit<N> {
	type Output = Option<AsymetricallyEncryptedBit<N>>;

	fn mul(self, other: &'a AsymetricallyEncryptedBit<N>) -> Self::Output {
		match &self.c * &other.c {
			None => None,
			Some(c) => Some(AsymetricallyEncryptedBit::<N>::new(c))
		}
	}
}