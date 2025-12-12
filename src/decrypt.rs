//loader/src/decrypt.rs

use aes::cipher::BlockDecryptMut;

/// AES-256-CBC decryption with PKCS7 padding.
/// Accepts:
/// - `encrypted`: ciphertext to decrypt
/// - `key`: 32-byte AES key
/// - `iv`: 16-byte CBC IV
///
/// Returns:
/// - `Ok(Vec<u8>)`: decrypted plaintext
/// - `Err(String)`: if key/iv/ciphertext is invalid or decryption fails
pub fn decrypt_simple_aes(encrypted: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, String> {
    use aes::Aes256;
    use cbc::Decryptor;
    use aes::cipher::{block_padding::Pkcs7, KeyIvInit};

    // Create a mutable buffer from input because decrypt_padded_mut operates in-place
    let mut buffer = encrypted.to_vec();

    // Create CBC decryption context from key and IV
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| format!("Erreur init déchiffreur: {:?}", e))?;

    // Perform the in-place decryption (with padding handling)
    let decrypted_data = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| format!("Erreur de déchiffrement: {:?}", e))?;

    // Return the plaintext as an owned Vec
    Ok(decrypted_data.to_vec())
}