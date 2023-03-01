use num_bigint::ToBigInt;


use crate::dghv::{ETA, key_gen};

#[test]
fn key_gen_test() {
	let mut min  = 2.to_bigint().unwrap();
	let mut max  = 2.to_bigint().unwrap();

	min = min.pow((ETA-1).try_into().unwrap());
	max = max.pow(ETA.try_into().unwrap());

	let key = key_gen();
	
	assert!(key >= min);
	assert!(key < max);
}