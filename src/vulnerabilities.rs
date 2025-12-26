use std::{error::Error, fmt::Display, str::FromStr};

use versions::Versioning;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct Range {
    pub(crate) start: Versioning,
    pub(crate) end: Versioning,
}

impl std::fmt::Debug for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Range")
            .field("start", &self.start.to_string())
            .field("end", &self.end.to_string())
            .finish()
    }
}
impl Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug)]
pub struct SeverityError {
    value: String,
}

impl Error for SeverityError {}

impl Display for SeverityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { value } = self;
        write!(f, "Could not parse \"{value}\" as a severity")
    }
}

impl FromStr for Severity {
    type Err = SeverityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            v => Err(SeverityError {
                value: v.to_string(),
            }),
        }
    }
}

#[derive(Debug)]
pub struct Vulnerability {
    pub(crate) id: String,
    pub(crate) description: String,
    pub(crate) severity: Option<Severity>,
    pub(crate) ranges: Vec<Range>,
}
