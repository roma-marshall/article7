use crate::identity::PublicProfile;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Contact {
    pub alias: String,
    pub profile: PublicProfile,
}

pub fn validate_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 64
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

