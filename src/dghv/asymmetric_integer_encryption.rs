use core::ops::{Add, Mul};

use rand::Rng;
use num_traits::Zero;
use num_bigint::RandBigInt;

use crate::dghv::{AsymetricEncryption, SymetricEncryption, SymetricallyEncryptedInteger};
use crate::dghv::symetric_bit_encryption::initial_noise_size;

pub struct AsymetricallyEncryptedInteger<const NB_ZEROS: usize, const NOISE_FACTOR: usize> {
	c: SymetricallyEncryptedInteger<NOISE_FACTOR>
}

impl<const NB_ZEROS: usize, const NOISE_FACTOR: usize> AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR> {
	fn new(c: SymetricallyEncryptedInteger<NOISE_FACTOR>) -> Self {
		Self{c:c}
	}
}

impl<const NB_ZEROS: usize, const NOISE_FACTOR: usize> AsymetricEncryption for AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR> {
	type MessageType = usize;
	type PublicKeyType = [SymetricallyEncryptedInteger<NOISE_FACTOR>; NB_ZEROS];
	type PrivateKeyType = <SymetricallyEncryptedInteger<NOISE_FACTOR> as SymetricEncryption>::KeyType;

	fn key_gen() -> (Self::PublicKeyType, Self::PrivateKeyType) {
		let sk = SymetricallyEncryptedInteger::<NOISE_FACTOR>::key_gen();

		let pk: [SymetricallyEncryptedInteger<NOISE_FACTOR>; NB_ZEROS] = 
			core::array::from_fn(|_| SymetricallyEncryptedInteger::<NOISE_FACTOR>::encrypt(0, &sk));

		return (pk, sk);
	}

	fn encrypt(m: usize, p: &Self::PublicKeyType) -> Self {
		let mut rng = rand::thread_rng();

		let mut nb_zeros_included = 0;
		let mut ret = 
			<SymetricallyEncryptedInteger<NOISE_FACTOR> as SymetricEncryption>::KeyType::zero();
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
		ret = &ret + NOISE_FACTOR*r;

		ret += m;

		return AsymetricallyEncryptedInteger::new(
			SymetricallyEncryptedInteger::<NOISE_FACTOR>::new(ret, (nb_zeros_included+1)*p[0].noise())
		);
	}

	fn decrypt(&self, sk: &Self::PrivateKeyType) -> usize {
		self.c.decrypt(sk)
	}
}

impl<'a, const NB_ZEROS: usize, const NOISE_FACTOR: usize> Add<&'a AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR>> for &'a AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR> {
	type Output = Option<AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR>>;

	fn add(self, other: &'a AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR>) -> Self::Output {
		Some(AsymetricallyEncryptedInteger::<NB_ZEROS, NOISE_FACTOR>::new((&self.c + &other.c)?))
	}
}
impl<'a, const NB_ZEROS: usize, const NOISE_FACTOR: usize> Mul<&'a AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR>> for &'a AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR> {
	type Output = Option<AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR>>;

	fn mul(self, other: &'a AsymetricallyEncryptedInteger<NB_ZEROS, NOISE_FACTOR>) -> Self::Output {
		Some(AsymetricallyEncryptedInteger::<NB_ZEROS, NOISE_FACTOR>::new((&self.c * &other.c)?))
	}
}