/// 节点能力位掩码
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Capabilities {
    pub bits: u8,
}

impl Capabilities {
    pub const RELAY_CAPABLE: u8 = 0x01;
    pub const WS_LISTENER: u8 = 0x02;
    pub const IPV6_INBOUND: u8 = 0x04;

    pub fn new() -> Self {
        Self { bits: 0 }
    }

    pub fn with(self, flag: u8) -> Self {
        Self { bits: self.bits | flag }
    }

    pub fn has(self, flag: u8) -> bool {
        self.bits & flag != 0
    }

    pub fn set(&mut self, flag: u8, enabled: bool) {
        if enabled {
            self.bits |= flag;
        } else {
            self.bits &= !flag;
        }
    }
}
