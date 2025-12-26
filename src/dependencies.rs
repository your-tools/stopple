use versions::Versioning;

pub struct Dependency {
    pub(crate) name: String,
    pub(crate) version: Versioning,
}

impl Dependency {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> String {
        self.version.to_string()
    }
}
