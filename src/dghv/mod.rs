
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

mod symetric_bit_encryption;
pub use symetric_bit_encryption::SymetricallyEncryptedBit;



