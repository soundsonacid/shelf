use std::ops::RangeInclusive;

#[derive(PartialEq, PartialOrd, Debug, Copy, Clone)]
pub enum SBPFVersion {
    V0,
    V1,
    V2,
    V3,
}

#[derive(Clone)]
pub struct Config {
    pub enabled_sbpf_versions: RangeInclusive<SBPFVersion>,
    pub enable_address_translation: bool,
    pub aligned_memory_mapping: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V3,
            enable_address_translation: true,
            aligned_memory_mapping: true,
        }
    }
}

impl Config {
    pub fn has_sbpf_version_enabled(&self, version: SBPFVersion) -> bool {
        self.enabled_sbpf_versions.contains(&version)
    }

    pub fn below_sbpf_version(&self, version: SBPFVersion) -> bool {
        version > *self.enabled_sbpf_versions.end()
    }
}
