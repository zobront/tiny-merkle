use alloc::vec::Vec;

/// Hasher is a trait used to provide a hashing algorithm for the library.
///
/// # Example
///
/// This example shows how to implement the sha256 algorithm
///
/// ```
/// use tiny_merkle::{Hasher};
/// use sha2::{Sha256, Digest, digest::FixedOutput};
///
/// #[derive(Clone)]
/// pub struct Sha256Hasher;
///
/// impl Hasher for Sha256Hasher {
///     type Hash = [u8; 32];
///
///     fn hash(data: &[u8]) -> [u8; 32] {
///         let mut hasher = Sha256::new();
///
///         hasher.update(data);
///         <[u8; 32]>::from(hasher.finalize_fixed())
///     }
/// }
/// ```
pub trait Hasher {
	#[cfg(not(feature = "rayon"))]
	type Hash: AsRef<[u8]> + Clone + Ord;

	#[cfg(feature = "rayon")]
	type Hash: AsRef<[u8]> + Clone + Ord + Send + Sync;

	/// Gets the hash of the byte sequence.
	fn hash(value: &[u8]) -> Self::Hash;
}

/// NoopHasher is a hasher that does not hash the input.
/// It is useful for testing.
pub struct NoopHasher;
impl Hasher for NoopHasher {
	type Hash = Vec<u8>;

	fn hash(value: &[u8]) -> Self::Hash {
		value.to_vec()
	}
}
