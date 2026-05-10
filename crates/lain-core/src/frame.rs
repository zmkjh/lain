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

fn encode_varint(value: u64, buf: &mut Vec<u8>) {
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

fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
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
}
