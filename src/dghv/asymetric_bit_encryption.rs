use core::ops::{Add, Mul};
use num_bigint::BigInt;
use crate::dghv::{AsymetricEncryption, SymetricEncryption, SymetricallyEncryptedBit};

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
	type PublicKeyType = SymetricallyEncryptedBit;
	type PrivateKeyType = BigInt;

	fn key_gen() -> (Self::PublicKeyType, Self::PrivateKeyType) {
		let sk = SymetricallyEncryptedBit::key_gen();

		let mut pk = SymetricallyEncryptedBit::encrypt(false, &sk);

		for _ in 0..N {
			pk = (&pk + &SymetricallyEncryptedBit::encrypt(false, &sk)).unwrap();
		}

		return (pk, sk);
	}

	fn encrypt(m: bool, p: &SymetricallyEncryptedBit) -> Self {
		let mut ret = p.cipher();
		if m {
			ret += 1;
		}
		return AsymetricallyEncryptedBit::new(SymetricallyEncryptedBit::new(ret, p.noise()));
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