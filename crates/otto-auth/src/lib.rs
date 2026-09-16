//! `otto-auth` — authentication and authorization, shared by every otto-*
//! service.
//!
//! Two layers that must not be conflated:
//!
//! - **Layer 2, who the human is**: [`login`] is the front door, over
//!   [`passkeys`] (WebAuthn, usernameless, phishing-resistant) and
//!   [`sessions`] (a console's browser cookie). Enterprise OIDC federation
//!   would join this layer later; it does not exist in this baseline (see
//!   `otto-tenant`'s auth migration docs).
//!
//!   **No email, anywhere.** There is no verification link, no recovery link,
//!   and no mailer — a passkey is the only factor, a second passkey is the
//!   only self-service way back in, and an org admin resetting a member's
//!   passkeys is the only assisted one. That is a product decision with a
//!   consequence worth stating plainly: signup takes no request body at all,
//!   so there is nothing submitted before a ceremony to answer differently
//!   about — the account-enumeration oracle a password or a returned secret
//!   used to leak through is closed by construction.
//! - **Layer 1, what a client may do**: the OAuth 2.1 authorization server and
//!   the token model. One identity database serves every otto-* resource
//!   server, and [`tokens::introspect`]'s audience check is what stops a
//!   token minted for one from being replayed against another — see
//!   `docs/specs/2026-09-15-otto-flags-design.md` §3 in the otto-flags repo.
//!
//! We implement published standards rather than anything bespoke — OAuth 2.1
//! (authorization code + PKCE S256 only), RFC 8414 AS metadata, RFC 9728
//! protected-resource metadata, RFC 7591 dynamic client registration, RFC 8707
//! resource indicators, RFC 7009 revocation. A non-standard server would not
//! merely fail an enterprise security review; MCP clients would be unable to
//! connect to it at all.
//!
//! No password is ever accepted, stored, or reset, and no cryptographic
//! primitive is hand-written — see [`crypto`] for what is used where.

pub mod crypto;
pub mod error;
pub mod login;
pub mod oauth;
pub mod passkeys;
pub mod ratelimit;
pub mod sessions;
pub mod tokens;

pub use error::{AuthError, Result};
pub use login::LoggedIn;
pub use sessions::Session;
pub use tokens::Principal;
