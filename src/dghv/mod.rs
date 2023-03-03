
#[cfg(test)]
mod test;

const LAMBDA: usize = 42;
const RHO: usize = 27;
const ETA: usize = 1026;
const GAMMA: usize = 150000;

pub trait SymetricEncryption {
	type KeyType;
	type MessageType;

	fn key_gen() -> Self::KeyType;
	fn encrypt(message: Self::MessageType, key: &Self::KeyType) -> Self;
	fn decrypt(&self, key: &Self::KeyType) -> Self::MessageType;
}

pub trait AsymetricEncryption {
	type PublicKeyType;
	type PrivateKeyType;
	type MessageType;

	fn key_gen() -> (Self::PublicKeyType, Self::PrivateKeyType);
	fn encrypt(message: Self::MessageType, pk: &Self::PublicKeyType) -> Self;
	fn decrypt(&self, sk: &Self::PrivateKeyType) -> Self::MessageType;
}

pub trait EncryptedInteger<const N: usize> {
	type CipherType;
	type NoiseType;

	fn cipher(&self) -> &Self::CipherType;
	fn noise_level(&self) -> &Self::NoiseType;
}

mod symetric_integer_encryption;
pub use symetric_integer_encryption::SymetricallyEncryptedInteger;

mod asymmetric_integer_encryption;
pub use asymmetric_integer_encryption::AsymetricallyEncryptedInteger;



