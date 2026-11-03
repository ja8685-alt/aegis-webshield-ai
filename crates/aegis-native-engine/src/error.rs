use std::error::Error;
use std::fmt::{Display, Formatter};

/// Validation error returned by the deployment-neutral contract models.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractError {
    field: &'static str,
    message: &'static str,
}

impl ContractError {
    /// Builds a bounded static validation error for deployment adapter contracts.
    pub const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    /// Contract field that failed validation.
    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl Display for ContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for ContractError {}
