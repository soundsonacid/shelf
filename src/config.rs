use std::ops::RangeInclusive;

#[derive(PartialEq, PartialOrd)]
pub enum SBPFVersion {
    V0,
    V1,
    V2,
    V3,
}

pub struct Config {
    enabled_sbpf_versions: RangeInclusive<SBPFVersion>,
}

impl Default for Config {
    fn default() -> Self {
        Self { enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V3 }
    }
}

impl Config {
    pub fn has_sbpf_version_enabled(&self, version: SBPFVersion) -> bool {
        self.enabled_sbpf_versions.contains(&version)
    }
}
