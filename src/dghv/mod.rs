
#[cfg(test)]
mod test;

const LAMBDA: usize = 42;
const RHO: usize = 27;
const ETA: usize = 1026;
const GAMMA: usize = 150000;

trait SymetricEncryption {
	type KeyType;
	type MessageType;

	fn key_gen() -> Self::KeyType;
	fn encrypt(message: Self::MessageType, key: &Self::KeyType) -> Self;
	fn decrypt(&self, key: &Self::KeyType) -> Self::MessageType;
}

trait AsymetricEncryption {
	type PublicKeyType;
	type PrivateKeyType;
	type MessageType;

	fn key_gen() -> (Self::PublicKeyType, Self::PrivateKeyType);
	fn encrypt(message: Self::MessageType, pk: &Self::PublicKeyType) -> Self;
	fn decrypt(&self, sk: &Self::PrivateKeyType) -> Self::MessageType;
}

mod symetric_bit_encryption;
pub use symetric_bit_encryption::SymetricallyEncryptedBit;

mod asymetric_bit_encryption;
pub use asymetric_bit_encryption::AsymetricallyEncryptedBit;



