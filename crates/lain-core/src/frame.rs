/// Lain 帧类型 (per §9.7.4)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Headers = 0x00,
    Data = 0x01,
    DataDgram = 0x02,
    Close = 0x03,
    Ping = 0x04,
    Pong = 0x05,
    PathChange = 0x06,
    StreamResume = 0x07,
    RelayConnect = 0x08,
    RelayData = 0x09,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Headers),
            0x01 => Some(Self::Data),
            0x02 => Some(Self::DataDgram),
            0x03 => Some(Self::Close),
            0x04 => Some(Self::Ping),
            0x05 => Some(Self::Pong),
            0x06 => Some(Self::PathChange),
            0x07 => Some(Self::StreamResume),
            0x08 => Some(Self::RelayConnect),
            0x09 => Some(Self::RelayData),
            _ => None,
        }
    }
}

pub const MAGIC: [u8; 3] = [0x4C, 0x41, 0x49]; // "LAI"

/// 编码 Lain 帧
pub fn encode_frame(stream_id: u64, frame_type: FrameType, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(8 + payload.len());
    f.extend_from_slice(&MAGIC);
    encode_varint(stream_id, &mut f);
    encode_varint(frame_type as u64, &mut f);
    encode_varint(payload.len() as u64, &mut f);
    f.extend_from_slice(payload);
    f
}

/// 解码 Lain 帧头，返回 (stream_id, frame_type, payload_len, header_bytes_read)
pub fn decode_frame_header(data: &[u8]) -> Option<(u64, FrameType, u64, usize)> {
    if data.len() < 3 || data[0..3] != MAGIC {
        return None;
    }
    let (sid, s_off) = decode_varint(&data[3..])?;
    let (ft, f_off) = decode_varint(&data[3 + s_off..])?;
    let (plen, p_off) = decode_varint(&data[3 + s_off + f_off..])?;
    let ft = FrameType::from_u8(ft as u8)?;
    let header_len = 3 + s_off + f_off + p_off;
    Some((sid, ft, plen, header_len))
}

pub fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    if value <= 63 {
        buf.push(value as u8);
    } else if value <= 16383 {
        buf.push(0x40 | ((value >> 8) as u8 & 0x3F));
        buf.push(value as u8);
    } else if value <= 1073741823 {
        buf.push(0x80 | ((value >> 24) as u8 & 0x3F));
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        buf.push(0xC0 | ((value >> 56) as u8 & 0x3F));
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
}

pub fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    let (val, len): (u64, usize) = if first & 0xC0 == 0 {
        (first as u64, 1)
    } else if first & 0xC0 == 0x40 {
        if data.len() < 2 { return None; }
        (((first & 0x3F) as u64) << 8 | data[1] as u64, 2)
    } else if first & 0xC0 == 0x80 {
        if data.len() < 4 { return None; }
        (((first & 0x3F) as u64) << 24
            | (data[1] as u64) << 16
            | (data[2] as u64) << 8
            | data[3] as u64, 4)
    } else {
        if data.len() < 8 { return None; }
        (((first & 0x3F) as u64) << 56
            | (data[1] as u64) << 48
            | (data[2] as u64) << 40
            | (data[3] as u64) << 32
            | (data[4] as u64) << 24
            | (data[5] as u64) << 16
            | (data[6] as u64) << 8
            | data[7] as u64, 8)
    };
    Some((val, len))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_frame() {
        let payload = b"hello";
        let frame = encode_frame(1, FrameType::Data, payload);
        let (sid, ft, plen, hlen) = decode_frame_header(&frame).unwrap();
        assert_eq!(sid, 1);
        assert_eq!(ft, FrameType::Data);
        assert_eq!(plen, 5);
        assert_eq!(&frame[hlen..hlen + 5], payload);
    }

    #[test]
    fn test_varint_roundtrip() {
        for v in [0, 1, 63, 64, 255, 16383, 16384, 65535, 1_000_000, 1_000_000_000] {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf);
            let (decoded, _) = decode_varint(&buf).unwrap();
            assert_eq!(v, decoded, "varint {v}");
        }
    }

    #[test]
    fn test_all_frame_types_roundtrip() {
        let cases: Vec<(FrameType, &str)> = vec![
            (FrameType::Headers, "Headers"),
            (FrameType::Data, "Data"),
            (FrameType::DataDgram, "DataDgram"),
            (FrameType::Close, "Close"),
            (FrameType::Ping, "Ping"),
            (FrameType::Pong, "Pong"),
            (FrameType::PathChange, "PathChange"),
            (FrameType::StreamResume, "StreamResume"),
            (FrameType::RelayConnect, "RelayConnect"),
            (FrameType::RelayData, "RelayData"),
        ];
        for (ft, name) in &cases {
            let payload = format!("hello {name}").into_bytes();
            let frame = encode_frame(42, *ft, &payload);
            let (sid, decoded_ft, plen, hlen) = decode_frame_header(&frame).unwrap();
            assert_eq!(sid, 42, "{name}: stream_id mismatch");
            assert_eq!(decoded_ft, *ft, "{name}: frame type mismatch");
            assert_eq!(plen as usize, payload.len(), "{name}: payload len mismatch");
            assert_eq!(&frame[hlen..hlen + payload.len()], &payload, "{name}: payload mismatch");
        }
    }

    #[test]
    fn test_frame_empty_payload() {
        let frame = encode_frame(0, FrameType::Ping, &[]);
        let (sid, ft, plen, hlen) = decode_frame_header(&frame).unwrap();
        assert_eq!(sid, 0);
        assert_eq!(ft, FrameType::Ping);
        assert_eq!(plen, 0);
        assert_eq!(hlen, frame.len()); // no payload beyond header
    }

    #[test]
    fn test_frame_large_payload() {
        let payload = vec![0xAAu8; 65536];
        let frame = encode_frame(1, FrameType::Data, &payload);
        let (sid, ft, plen, hlen) = decode_frame_header(&frame).unwrap();
        assert_eq!(sid, 1);
        assert_eq!(ft, FrameType::Data);
        assert_eq!(plen as usize, 65536);
        assert_eq!(&frame[hlen..hlen + 65536], &payload);
    }

    #[test]
    fn test_decode_frame_rejects_invalid_magic() {
        assert!(decode_frame_header(&[0x00, 0x00, 0x00]).is_none());
        assert!(decode_frame_header(&[0x4C, 0x41, 0x00]).is_none()); // L A X
    }

    #[test]
    fn test_decode_frame_rejects_too_short() {
        assert!(decode_frame_header(&[]).is_none());
        assert!(decode_frame_header(&[0x4C, 0x41]).is_none());
    }

    #[test]
    fn test_decode_frame_rejects_unknown_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        encode_varint(1, &mut buf);
        encode_varint(0xFFu64, &mut buf); // unknown type
        encode_varint(0, &mut buf);
        assert!(decode_frame_header(&buf).is_none());
    }

    #[test]
    fn test_varint_decode_truncated() {
        // 2-byte varint with only 1 byte available
        let buf = vec![0x7Fu8]; // 0x40 | something: means 2-byte
        assert!(decode_varint(&buf).is_none());

        // 4-byte varint with only 3 bytes
        let buf = vec![0x8Cu8, 0x00, 0x00]; // 0x80 | something: means 4-byte
        assert!(decode_varint(&buf).is_none());

        // 8-byte varint with only 5 bytes
        let buf = vec![0xC0u8, 0x00, 0x00, 0x00, 0x00]; // 0xC0: means 8-byte
        assert!(decode_varint(&buf).is_none());
    }

    #[test]
    fn test_varint_decode_empty() {
        assert!(decode_varint(&[]).is_none());
    }

    #[test]
    fn test_frame_from_u8_all_valid() {
        for v in 0x00..=0x09u8 {
            assert!(FrameType::from_u8(v).is_some(), "frame type 0x{v:02X} should be valid");
        }
    }

    #[test]
    fn test_frame_from_u8_invalid() {
        for v in 0x0A..=0x7Fu8 {
            assert!(FrameType::from_u8(v).is_none(), "frame type 0x{v:02X} should be invalid");
        }
    }
}
