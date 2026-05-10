/// 256-bit PeerID = SHA256(Ed25519 公钥)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub [u8; 32]);

// serde: 序列化为 hex 字符串
impl serde::Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let hex: String = self.0.iter().map(|b| format!("{:02x}", b)).collect();
        s.serialize_str(&hex)
    }
}

impl<'de> serde::Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        let bytes = hex::decode(hex.as_ref())
            .map_err(|_| serde::de::Error::custom("invalid hex for PeerId"))?;
        let mut id = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("PeerId must be 32 bytes"));
        }
        id.copy_from_slice(&bytes);
        Ok(PeerId(id))
    }
}

impl PeerId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("PeerId must be 32 bytes".to_string());
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(PeerId(id))
    }

    /// XOR 距离，用于 Kademlia DHT
    pub fn distance(&self, other: &PeerId) -> [u8; 32] {
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = self.0[i] ^ other.0[i];
        }
        dist
    }

    /// XOR 距离的前导零位数 = bucket index
    pub fn bucket_index(&self, other: &PeerId) -> usize {
        let dist = self.distance(other);
        let mut bits = 0;
        for byte in dist {
            if byte == 0 {
                bits += 8;
            } else {
                bits += byte.leading_zeros() as usize;
                break;
            }
        }
        bits.min(255)
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerId({})", self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_serde_roundtrip() {
        let id = PeerId([1u8; 32]);
        let json = serde_json::to_string(&id).unwrap();
        let back: PeerId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn test_peer_id_to_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        let id = PeerId(bytes);
        assert!(id.to_hex().starts_with("abcd"));
    }
}
