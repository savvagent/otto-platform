//! Typed identifiers.
//!
//! These are newtypes rather than bare `Uuid`/`String` so that the compiler
//! rejects passing a `UserId` where an `OrgId` belongs. In a multi-tenant system
//! that mix-up is the single highest-consequence typo available, and it is
//! otherwise invisible: both are `Uuid`, both come from the same request, and
//! the query still runs.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
        #[serde(transparent)]
        #[sqlx(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }

        // Written out rather than derived. A derive on a newtype produces a
        // schema named after the wrapper with the inner type nested inside;
        // over the wire these *are* UUID strings, and that is what an MCP
        // client's schema should say.
        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($name)).into()
            }

            fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({
                    "type": "string",
                    "format": "uuid",
                    "description": $doc,
                })
            }

            fn inline_schema() -> bool {
                true
            }
        }
    };
}

uuid_id!(
    OrgId,
    "The tenant boundary. Every tenant-scoped operation takes one."
);
uuid_id!(
    UserId,
    "A global human identity, shared across every org they belong to."
);
uuid_id!(TeamId, "A team within one org.");
