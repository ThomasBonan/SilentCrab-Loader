use aes::cipher::BlockDecryptMut; // Ajout important


pub fn decrypt_simple_aes(encrypted: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, String> {
    use aes::Aes256;
    use cbc::Decryptor;
    use aes::cipher::{block_padding::Pkcs7, KeyIvInit};

    // On copie dans un buffer mutable car l'algo modifie la data
    let mut buffer = encrypted.to_vec();

    // Crée le déchiffreur avec clé et IV
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| format!("Erreur init déchiffreur: {:?}", e))?;

    // Déchiffrement avec padding PKCS7
    let decrypted_data = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| format!("Erreur de déchiffrement: {:?}", e))?;

    // Copie les données utiles dans un Vec à retourner
    Ok(decrypted_data.to_vec())
}