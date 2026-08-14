extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::FileError;

pub const MAX_COMPONENT_BYTES: usize = 255;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_COMPONENTS: usize = 64;
pub const MAX_SYMLINKS: usize = 40;

/// A normalized selector relative to one `FileTreeRoot` capability.
///
/// It deliberately contains no capability label. A string can select only
/// after admission has separately supplied a root capability.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RelPath {
    components: Vec<String>,
}

impl RelPath {
    pub fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    pub fn parse(input: &str) -> Result<Self, FileError> {
        if input.len() > MAX_PATH_BYTES || input.starts_with('/') {
            return Err(FileError::InvalidPath);
        }
        let mut components = Vec::new();
        for raw in input.split('/') {
            match raw {
                "" | "." => continue,
                ".." => {
                    if components.pop().is_none() {
                        return Err(FileError::EscapeRoot);
                    }
                }
                name => {
                    validate_name(name)?;
                    if components.len() == MAX_COMPONENTS {
                        return Err(FileError::PathTooLong);
                    }
                    components.push(name.to_string());
                }
            }
        }
        Ok(Self { components })
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }

    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    pub fn to_selector_string(&self) -> String {
        self.components.join("/")
    }

    pub fn parent_and_name(&self) -> Result<(Self, &str), FileError> {
        let (name, parent) = self
            .components
            .split_last()
            .ok_or(FileError::RootProtected)?;
        Ok((
            Self {
                components: parent.to_vec(),
            },
            name,
        ))
    }

    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    pub fn joined_name(&self, name: &str) -> Result<Self, FileError> {
        validate_name(name)?;
        let mut components = self.components.clone();
        components.push(name.to_string());
        Self::from_components(components)
    }

    pub fn relative_from_directory(directory: &Self, target: &Self) -> String {
        let common = directory
            .components
            .iter()
            .zip(&target.components)
            .take_while(|(left, right)| left == right)
            .count();
        let mut parts = Vec::new();
        for _ in common..directory.components.len() {
            parts.push("..".to_string());
        }
        parts.extend(target.components[common..].iter().cloned());
        if parts.is_empty() {
            ".".to_string()
        } else {
            parts.join("/")
        }
    }

    pub(crate) fn from_components(components: Vec<String>) -> Result<Self, FileError> {
        if components.len() > MAX_COMPONENTS {
            return Err(FileError::PathTooLong);
        }
        let bytes = components.iter().map(|x| x.len() + 1).sum::<usize>();
        if bytes > MAX_PATH_BYTES {
            return Err(FileError::PathTooLong);
        }
        Ok(Self { components })
    }

    pub(crate) fn joined_from(parent: &[String], target: &str) -> Result<Self, FileError> {
        if target.starts_with('/') || target.contains('@') {
            return Err(FileError::EscapeRoot);
        }
        let mut output = parent.to_vec();
        for raw in target.split('/') {
            match raw {
                "" | "." => {}
                ".." => {
                    if output.pop().is_none() {
                        return Err(FileError::EscapeRoot);
                    }
                }
                name => {
                    validate_name(name)?;
                    output.push(name.to_string());
                    if output.len() > MAX_COMPONENTS {
                        return Err(FileError::PathTooLong);
                    }
                }
            }
        }
        Self::from_components(output)
    }
}

pub fn validate_name(name: &str) -> Result<(), FileError> {
    if name.is_empty() || name == "." || name == ".." || name.len() > MAX_COMPONENT_BYTES {
        return Err(FileError::InvalidName);
    }
    if name
        .as_bytes()
        .iter()
        .any(|byte| *byte == b'/' || *byte <= 0x1f || *byte == 0x7f)
    {
        return Err(FileError::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_is_root_bounded() {
        assert_eq!(
            RelPath::parse("a//./b/../c").unwrap().components(),
            &["a", "c"]
        );
        assert_eq!(RelPath::parse("../a"), Err(FileError::EscapeRoot));
        assert_eq!(RelPath::parse("/a"), Err(FileError::InvalidPath));
    }

    #[test]
    fn names_fail_closed() {
        assert!(validate_name("ok name").is_ok());
        for name in [".", "..", "a/b", "a\0b", "a\nb", "a\u{7f}b"] {
            assert_eq!(validate_name(name), Err(FileError::InvalidName));
        }
    }
}
