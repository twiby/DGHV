use core::ops::{Add, Mul};

use rand::Rng;
use num_traits::Zero;
use num_bigint::RandBigInt;

use crate::dghv::{AsymetricEncryption, SymetricEncryption, SymetricallyEncryptedByte};
use crate::dghv::symetric_bit_encryption::initial_noise_size;

pub struct AsymetricallyEncryptedByte<const N: usize> {
	c: SymetricallyEncryptedByte
}

impl<const N: usize> AsymetricallyEncryptedByte<N> {
	fn new(c: SymetricallyEncryptedByte) -> Self {
		Self{c:c}
	}
}

impl<const N: usize> AsymetricEncryption for AsymetricallyEncryptedByte<N> {
	type MessageType = u8;
	type PublicKeyType = [SymetricallyEncryptedByte; N];
	type PrivateKeyType = <SymetricallyEncryptedByte as SymetricEncryption>::KeyType;

	fn key_gen() -> (Self::PublicKeyType, Self::PrivateKeyType) {
		let sk = SymetricallyEncryptedByte::key_gen();

		let pk: [SymetricallyEncryptedByte; N] = 
			core::array::from_fn(|_| SymetricallyEncryptedByte::encrypt(0u8, &sk));

		return (pk, sk);
	}

	fn encrypt(m: u8, p: &Self::PublicKeyType) -> Self {
		let mut rng = rand::thread_rng();

		let mut nb_zeros_included = 0;
		let mut ret = 
			<SymetricallyEncryptedByte as SymetricEncryption>::KeyType::zero();
		for pi in p {
			if rng.gen_bool(0.5) {
				ret = ret + &pi.cipher();
				nb_zeros_included += 1;
			}
		}
		
		if nb_zeros_included == 0 {
			ret = ret + &p[0].cipher();
			nb_zeros_included = 1;
		}

		// r is between -p/4 and p/4
		let min_r = -initial_noise_size();
		let max_r = initial_noise_size();
		let r = rng.gen_bigint_range(&min_r, &max_r);
		ret = &ret + 256*r;

		ret += m;

		return AsymetricallyEncryptedByte::new(
			SymetricallyEncryptedByte::new(ret, (nb_zeros_included+1)*p[0].noise())
		);
	}

	fn decrypt(&self, sk: &Self::PrivateKeyType) -> u8 {
		self.c.decrypt(sk)
	}
}

impl<'a, const N: usize> Add<&'a AsymetricallyEncryptedByte<N>> for &'a AsymetricallyEncryptedByte<N> {
	type Output = Option<AsymetricallyEncryptedByte<N>>;

	fn add(self, other: &'a AsymetricallyEncryptedByte<N>) -> Self::Output {
		Some(AsymetricallyEncryptedByte::<N>::new((&self.c + &other.c)?))
	}
}
impl<'a, const N: usize> Mul<&'a AsymetricallyEncryptedByte<N>> for &'a AsymetricallyEncryptedByte<N> {
	type Output = Option<AsymetricallyEncryptedByte<N>>;

	fn mul(self, other: &'a AsymetricallyEncryptedByte<N>) -> Self::Output {
		Some(AsymetricallyEncryptedByte::<N>::new((&self.c * &other.c)?))
	}
}