use authsvc_core::AuthError;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use rsa::Oaep;
use rsa::pkcs8::DecodePrivateKey;
use sha2::Sha256;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const XMLENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const RSA_OAEP: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

/// Decrypt `EncryptedAssertion` elements in a SAML response, returning plaintext XML.
pub fn decrypt_encrypted_assertions(xml: &str, sp_private_key_pem: &str) -> Result<String, AuthError> {
    if !xml.contains("EncryptedAssertion") && !xml.contains("xenc:EncryptedData") {
        return Ok(xml.to_string());
    }

    let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(sp_private_key_pem)
        .map_err(|e| AuthError::Validation(format!("invalid SP private key: {e}")))?;

    let mut result = xml.to_string();
    while let Some(start) = result.find("<saml:EncryptedAssertion") {
        let end_tag = "</saml:EncryptedAssertion>";
        let end = result[start..]
            .find(end_tag)
            .map(|i| start + i + end_tag.len())
            .ok_or_else(|| AuthError::Validation("malformed EncryptedAssertion".into()))?;
        let encrypted = &result[start..end];
        let plaintext = decrypt_encrypted_assertion(encrypted, &private_key)?;
        result.replace_range(start..end, &plaintext);
    }
    Ok(result)
}

fn decrypt_encrypted_assertion(
    encrypted_xml: &str,
    private_key: &rsa::RsaPrivateKey,
) -> Result<String, AuthError> {
    let cipher_value = extract_tag_text(encrypted_xml, "xenc:CipherValue")
        .or_else(|| extract_tag_text(encrypted_xml, "CipherValue"))
        .ok_or_else(|| AuthError::Validation("missing EncryptedData CipherValue".into()))?;

    let encrypted_key_b64 = encrypted_xml
        .find("EncryptedKey")
        .and_then(|_| {
            let key_section = encrypted_xml.split("EncryptedKey").nth(1)?;
            extract_tag_text(key_section, "xenc:CipherValue")
                .or_else(|| extract_tag_text(key_section, "CipherValue"))
        })
        .ok_or_else(|| AuthError::Validation("missing EncryptedKey CipherValue".into()))?;

    let key_algorithm = extract_attribute(encrypted_xml, "EncryptionMethod", "Algorithm")
        .unwrap_or_else(|| RSA_OAEP.to_string());

    let encrypted_key = base64::engine::general_purpose::STANDARD
        .decode(encrypted_key_b64.trim())
        .map_err(|e| AuthError::Validation(format!("invalid encrypted key: {e}")))?;

    let symmetric_key = if key_algorithm.contains("rsa-oaep") {
        let padding = Oaep::new::<Sha256>();
        private_key
            .decrypt(padding, &encrypted_key)
            .map_err(|e| AuthError::Validation(format!("RSA-OAEP decrypt failed: {e}")))?
    } else {
        return Err(AuthError::Validation(format!(
            "unsupported key transport algorithm: {key_algorithm}"
        )));
    };

    let data_algorithm = find_encrypted_data_algorithm(encrypted_xml)?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(cipher_value.trim())
        .map_err(|e| AuthError::Validation(format!("invalid ciphertext: {e}")))?;

    let iv = extract_iv(encrypted_xml, &ciphertext)?;

    let plaintext = match data_algorithm.as_str() {
        AES256_CBC => {
            if symmetric_key.len() < 32 {
                return Err(AuthError::Validation("invalid AES-256-CBC key material".into()));
            }
            decrypt_aes_cbc::<Aes256CbcDec>(&symmetric_key[..32], &iv, &ciphertext)?
        }
        AES128_CBC => {
            if symmetric_key.len() < 16 {
                return Err(AuthError::Validation("invalid AES-128-CBC key material".into()));
            }
            decrypt_aes_cbc::<Aes128CbcDec>(&symmetric_key[..16], &iv, &ciphertext)?
        }
        other => {
            return Err(AuthError::Validation(format!(
                "unsupported content encryption algorithm: {other}"
            )));
        }
    };

    String::from_utf8(plaintext)
        .map_err(|e| AuthError::Validation(format!("decrypted assertion is not UTF-8: {e}")))
}

fn decrypt_aes_cbc<D>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AuthError>
where
    D: KeyIvInit + BlockDecryptMut,
{
    let mut buf = ciphertext.to_vec();
    let plaintext = D::new_from_slices(key, iv)
        .map_err(|e| AuthError::Validation(format!("AES cipher init failed: {e}")))?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| AuthError::Validation(format!("AES decrypt failed: {e}")))?;
    Ok(plaintext.to_vec())
}

fn extract_iv(encrypted_xml: &str, ciphertext: &[u8]) -> Result<Vec<u8>, AuthError> {
    if let Some(b64) = extract_attribute(encrypted_xml, "xenc:CipherData", "IV") {
        return base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| AuthError::Validation(format!("invalid IV: {e}")));
    }
    if ciphertext.len() >= 16 {
        return Ok(ciphertext[..16].to_vec());
    }
    Err(AuthError::Validation("missing IV for encrypted assertion".into()))
}

fn find_encrypted_data_algorithm(xml: &str) -> Result<String, AuthError> {
    if xml.contains(AES256_CBC) {
        return Ok(AES256_CBC.to_string());
    }
    if xml.contains(AES128_CBC) {
        return Ok(AES128_CBC.to_string());
    }
    extract_attribute(xml, "EncryptionMethod", "Algorithm")
        .filter(|a| a.starts_with(XMLENC_NS))
        .ok_or_else(|| AuthError::Validation("unknown content encryption algorithm".into()))
}

fn extract_tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let after = &xml[start..];
    let content_start = after.find('>')? + 1;
    let rest = &after[content_start..];
    let end = rest.find('<')?;
    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn extract_attribute(xml: &str, near_tag: &str, attr: &str) -> Option<String> {
    let tag_pos = xml.find(near_tag)?;
    let section = &xml[tag_pos..];
    let pattern = format!("{attr}=\"");
    let start = section.find(&pattern)? + pattern.len();
    let rest = &section[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
