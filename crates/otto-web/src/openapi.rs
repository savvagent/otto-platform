//! The OpenAPI 3.1 document, rendered from [`crate::catalog`].
//!
//! The same list the router is built from, read a second way. A route that
//! exists is described, because describing it and mounting it are the same
//! declaration — see the catalog's module docs for why that is the shape chosen.
//!
//! Component schemas are hand-written here rather than derived from the Rust
//! types. That keeps OpenAPI's vocabulary out of `otto-core`, which has no business
//! carrying a documentation dependency for a surface it does not serve.

use std::sync::{Arc, OnceLock};

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::catalog::{catalog, Auth, Endpoint};
use crate::state::AppState;

/// `GET /api/openapi.json`.
pub async fn serve(State(_state): State<AppState>) -> Json<Value> {
    static DOC: OnceLock<Arc<Value>> = OnceLock::new();
    let doc = DOC.get_or_init(|| Arc::new(document(&catalog())));
    Json((**doc).clone())
}

pub fn document(endpoints: &[Endpoint]) -> Value {
    let mut paths = serde_json::Map::new();

    for endpoint in endpoints {
        let entry = paths
            .entry(endpoint.path.to_string())
            .or_insert_with(|| json!({}));

        let mut operation = json!({
            "operationId": endpoint.operation_id(),
            "summary": endpoint.summary,
            "description": endpoint.description,
            "tags": [tag_for(endpoint.path)],
            "responses": responses(endpoint),
        });

        let params = endpoint
            .path_params()
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "in": "path",
                    "required": true,
                    "description": param_description(name),
                    "schema": { "type": "string" },
                })
            })
            .collect::<Vec<_>>();

        if !params.is_empty() {
            operation["parameters"] = json!(params);
        }

        if let Some(schema) = endpoint.request {
            operation["requestBody"] = json!({
                "required": true,
                "content": { "application/json": { "schema": reference(schema) } },
            });
        }

        if endpoint.auth != Auth::Public {
            operation["security"] = json!([{ "sessionCookie": [] }]);
        }
        operation["x-otto-auth"] = json!(endpoint.auth.as_str());

        entry[endpoint.verb.as_str()] = operation;
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "otto platform API",
            "version": env!("CARGO_PKG_VERSION"),
            "description":
                "The identity and account REST surface, and the OAuth 2.1 authorization \
                 server for every registered otto-* resource server. Authentication is a \
                 session cookie (`__Host-otto_session`), set by the sign-in endpoints; \
                 the resource servers themselves use bearer tokens and are described by \
                 their own metadata documents.",
        },
        "components": {
            "securitySchemes": {
                "sessionCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": crate::session::COOKIE_NAME,
                    "description":
                        "Set on sign-in. HttpOnly, Secure, SameSite=Lax — browsers \
                         send it automatically; it cannot be read from script.",
                },
            },
            "schemas": components(),
        },
        "paths": paths,
    })
}

fn reference(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

/// The response block. Every endpoint can fail the same four ways, and saying
/// so once here is what makes the document usable without reading the source.
fn responses(endpoint: &Endpoint) -> Value {
    let success = match (endpoint.verb, endpoint.response) {
        (_, Some(schema)) => json!({
            "description": "Success",
            "content": { "application/json": { "schema": reference(schema) } },
        }),
        (crate::catalog::Verb::Delete, None) | (_, None) => json!({ "description": "Success" }),
    };

    let error = json!({
        "description": "Failure",
        "content": { "application/json": { "schema": reference("Error") } },
    });

    let mut responses = json!({
        "400": error,
        "500": error,
    });
    responses[endpoint.success.to_string()] = success;

    if endpoint.auth != Auth::Public {
        responses["401"] = error.clone();
    }
    if endpoint.auth.needs_org() {
        // 404 rather than 403 for an org you are not in — see `OrgCtx`.
        responses["403"] = error.clone();
        responses["404"] = error;
    }

    responses
}

fn param_description(name: &str) -> &'static str {
    match name {
        "org" => "Org slug.",
        "team" => "Team slug.",
        "user" => "User id (UUID).",
        "id" => "Resource id (UUID).",
        _ => "",
    }
}

fn tag_for(path: &str) -> &'static str {
    if path.starts_with("/oauth") || path.starts_with("/.well-known") {
        "oauth"
    } else if path.starts_with("/sso") || path.contains("/sso/") {
        "sso"
    } else if path.starts_with("/api/auth") {
        "auth"
    } else if path.starts_with("/api/me") {
        "me"
    } else if path.contains("/teams") {
        "teams"
    } else if path.contains("/tokens") {
        "tokens"
    } else if path.contains("/invites") {
        "invites"
    } else if path.contains("/usage") || path.contains("/audit") {
        "billing"
    } else {
        "orgs"
    }
}

/// The component schemas the catalog refers to by name.
///
/// Split across several functions because `serde_json::json!` is recursive and
/// one literal this size exhausts the macro recursion limit — a compile error,
/// not a runtime one, but a confusing enough compile error to be worth avoiding.
/// A new group of schemas goes in a new function for the same reason; adding
/// them to an existing one is how the limit gets hit again.
fn components() -> Value {
    let mut all = serde_json::Map::new();
    for group in [
        entity_schemas(),
        sso_schemas(),
        response_schemas(),
        request_schemas(),
    ] {
        let Value::Object(map) = group else {
            unreachable!("each schema group is an object literal")
        };
        all.extend(map);
    }
    Value::Object(all)
}

/// Enterprise OIDC federation — connection/domain admin, and the two sign-in
/// ceremonies. Its own group because the
/// entity literal is already at the `json!` recursion limit.
fn sso_schemas() -> Value {
    let uuid = json!({ "type": "string", "format": "uuid" });
    let timestamp = json!({ "type": "string", "format": "date-time" });

    let idp_connection = json!({
        "type": "object",
        "description":
            "One org's bound identity provider. The client secret is never returned by any \
             endpoint — it is sealed at rest and opened only for the duration of a token \
             exchange.",
        "properties": {
            "id": uuid,
            "orgId": uuid,
            "issuer": { "type": "string" },
            "clientId": { "type": "string" },
            "discovery": {
                "type": "object",
                "description": "The fetched /.well-known/openid-configuration document, cached.",
            },
            "createdAt": timestamp,
        },
        "required": ["id", "orgId", "issuer", "clientId", "discovery", "createdAt"],
    });

    let claimed_domain = json!({
        "type": "object",
        "description":
            "A globally-unique email domain claimed by this org, with the exact TXT record \
             to publish. verifiedAt is null until the DNS lookup succeeds.",
        "properties": {
            "orgId": uuid,
            "domain": { "type": "string" },
            "verificationToken": { "type": "string" },
            "verifiedAt": { "type": ["string", "null"], "format": "date-time" },
            "createdAt": timestamp,
            "txtRecordName": {
                "type": "string",
                "description": "The TXT record name to publish, e.g. _otto-verify.acme.com.",
            },
            "txtRecordValue": {
                "type": "string",
                "description": "The exact TXT record value to publish.",
            },
        },
        "required": [
            "orgId",
            "domain",
            "verificationToken",
            "createdAt",
            "txtRecordName",
            "txtRecordValue",
        ],
    });

    json!({
        "SsoStartRequest": {
            "type": "object",
            "description":
                "Only used by /api/auth/sso/start — /api/me/sso/link/start takes no body, \
                 it derives the domain from the caller's own account email.",
            "properties": {
                "email": { "type": "string" },
                "next": {
                    "type": "string",
                    "description":
                        "Optional. A path on this origin (one leading `/`, not `//` or `/\\`) \
                         to land on after signing in, such as the /oauth/authorize URL the \
                         login page was reached from. Anything else is ignored.",
                },
            },
            "required": ["email"],
        },
        "SsoStartResponse": {
            "type": "object",
            "properties": {
                "redirectUrl": {
                    "type": "string",
                    "description": "Navigate the browser here to begin the IdP's authorization-code flow.",
                },
            },
            "required": ["redirectUrl"],
        },
        "SsoConnectionRequest": {
            "type": "object",
            "properties": {
                "issuer": { "type": "string" },
                "clientId": { "type": "string" },
                "clientSecret": {
                    "type": "string",
                    "description": "Write-only. Never round-tripped back from any endpoint.",
                },
            },
            "required": ["issuer", "clientId", "clientSecret"],
        },
        "IdpConnection": idp_connection,
        "ClaimDomainRequest": {
            "type": "object",
            "properties": { "domain": { "type": "string" } },
            "required": ["domain"],
        },
        "ClaimedDomain": claimed_domain,
        "ClaimedDomainList": { "type": "array", "items": reference("ClaimedDomain") },
        "VerifyDomainResponse": {
            "type": "object",
            "description":
                "false is not an error — DNS has not propagated yet, and the admin can retry.",
            "properties": { "verified": { "type": "boolean" } },
            "required": ["verified"],
        },
        "EnforceSsoRequest": {
            "type": "object",
            "properties": { "enforceSso": { "type": "boolean" } },
            "required": ["enforceSso"],
        },
    })
}

/// The domain objects — what `otto-core` returns, as the wire sees it.
fn entity_schemas() -> Value {
    let timestamp = json!({ "type": "string", "format": "date-time" });
    let uuid = json!({ "type": "string", "format": "uuid" });
    let role = json!({ "type": "string", "enum": ["owner", "admin", "member"] });

    let locale = {
        let mut values: Vec<Value> = otto_core::i18n::SUPPORTED_LOCALES
            .iter()
            .map(|l| json!(l))
            .collect();
        values.push(Value::Null);
        json!({
            "type": ["string", "null"],
            "enum": values,
            "description": "The console language, or null to follow the browser's Accept-Language.",
        })
    };

    let user = json!({
        "type": "object",
        "properties": {
            "id": uuid,
            "email": {
                "type": ["string", "null"],
                "format": "email",
                "description":
                    "Absent until the account sets one. A passkey is what creates an \
                     account, so there is a real window — and, for anyone who never \
                     bothers, a permanent state — with no address.",
            },
            "name": { "type": ["string", "null"] },
            "label": {
                "type": "string",
                "description":
                    "Generated words that name this account in a credential vault's \
                     picker — never an identifier, and never unique.",
                "examples": ["brisk-harbor-42"],
            },
            "locale": locale,
            "createdAt": timestamp,
            "disabledAt": { "type": ["string", "null"], "format": "date-time" },
        },
        "required": ["id", "label", "createdAt"],
    });

    let org = json!({
        "type": "object",
        "properties": {
            "id": uuid,
            "slug": { "type": "string" },
            "name": { "type": "string" },
            "plan": { "type": "string", "enum": ["free", "team", "business", "enterprise"] },
            "enforceSso": { "type": "boolean" },
            "createdAt": timestamp,
        },
        "required": ["id", "slug", "name", "plan"],
    });

    let membership = json!({
        "type": "object",
        "description": "One org this account belongs to, and the role it holds there.",
        "properties": {
            "orgId": uuid,
            "userId": uuid,
            "role": role,
            "orgSlug": { "type": "string" },
            "orgName": { "type": "string" },
            "plan": { "type": "string" },
        },
        "required": ["orgId", "userId", "role", "orgSlug", "orgName"],
    });

    let org_member = json!({
        "type": "object",
        "properties": {
            "id": uuid,
            "email": { "type": ["string", "null"] },
            "name": { "type": ["string", "null"] },
            "label": { "type": "string", "examples": ["brisk-harbor-42"] },
            "role": role,
            "joinedAt": timestamp,
            "disabledAt": { "type": ["string", "null"], "format": "date-time" },
        },
        "required": ["id", "label", "role", "joinedAt"],
    });

    let team = json!({
        "type": "object",
        "properties": {
            "id": uuid,
            "orgId": uuid,
            "slug": { "type": "string" },
            "name": { "type": "string" },
            "createdAt": timestamp,
        },
        "required": ["id", "orgId", "slug", "name"],
    });

    let invite = json!({
        "type": "object",
        "properties": {
            "id": uuid,
            "orgId": uuid,
            "email": { "type": "string" },
            "role": role,
            "invitedBy": { "type": ["string", "null"], "format": "uuid" },
            "expiresAt": timestamp,
            "acceptedAt": { "type": ["string", "null"], "format": "date-time" },
            "createdAt": timestamp,
        },
        "required": ["id", "orgId", "email", "role", "expiresAt"],
    });

    json!({
        "Error": {
            "type": "object",
            "description":
                "Every failure. `code` is stable and safe to branch on; `message` is \
                 written to be shown to a person.",
            "properties": {
                "error": {
                    "type": "object",
                    "properties": {
                        "code": { "type": "string", "examples": ["invalid_credentials"] },
                        "message": { "type": "string" },
                    },
                    "required": ["code", "message"],
                },
            },
            "required": ["error"],
        },
        "User": user,
        "Org": org,
        "Membership": membership,
        "MembershipList": { "type": "array", "items": reference("Membership") },
        "OrgMember": org_member,
        "OrgMemberList": { "type": "array", "items": reference("OrgMember") },
        "Team": team,
        "TeamList": { "type": "array", "items": reference("Team") },
        "TeamMember": {
            "type": "object",
            "properties": {
                "userId": uuid,
                "email": { "type": ["string", "null"] },
                "name": { "type": ["string", "null"] },
                "label": { "type": "string", "examples": ["brisk-harbor-42"] },
                "joinedAt": timestamp,
            },
            "required": ["userId", "label", "joinedAt"],
        },
        "TeamMemberList": { "type": "array", "items": reference("TeamMember") },
        "Invite": invite,
        "InviteList": { "type": "array", "items": reference("Invite") },
        "Session": {
            "type": "object",
            "properties": {
                "id": uuid,
                "userId": uuid,
                "expiresAt": timestamp,
                "createdAt": timestamp,
            },
            "required": ["id", "userId", "expiresAt", "createdAt"],
        },
        "SessionList": { "type": "array", "items": reference("Session") },
        "TokenSummary": {
            "type": "object",
            "description": "A live credential. Never includes the token itself.",
            "properties": {
                "id": uuid,
                "name": { "type": ["string", "null"] },
                "kind": { "type": "string", "enum": ["oauth", "pat"] },
                "clientId": { "type": ["string", "null"] },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "createdAt": timestamp,
                "lastUsedAt": { "type": ["string", "null"], "format": "date-time" },
                "expiresAt": timestamp,
            },
            "required": ["id", "kind", "scopes", "createdAt", "expiresAt"],
        },
        "TokenSummaryList": { "type": "array", "items": reference("TokenSummary") },
        "MintedToken": {
            "type": "object",
            "description": "Shown once. Only a SHA-256 hash of `token` is stored.",
            "properties": {
                "token": { "type": "string", "examples": ["otto_pat_…"] },
                "id": uuid,
                "name": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "resource": {
                    "type": "string",
                    "description": "The resource server this token is audienced for.",
                },
            },
            "required": ["token", "id", "scopes", "resource"],
        },
        "UsageStatus": {
            "type": "object",
            "description":
                "This period's metered usage across every otto-* service. \
                 `billableUsed` counts only billable calls; `totalCalls` counts every \
                 call, free ones included.",
            "properties": {
                "plan": { "type": "string" },
                "includedOps": { "type": "integer" },
                "billableUsed": { "type": "integer" },
                "remaining": { "type": "integer" },
                "totalCalls": { "type": "integer" },
                "periodStart": { "type": "string", "format": "date" },
                "warning": { "type": "boolean" },
                "hardStop": { "type": "boolean" },
                "enforced": { "type": "boolean" },
            },
            "required": ["plan", "includedOps", "billableUsed", "remaining"],
        },
        "AuditEvent": {
            "type": "object",
            "properties": {
                "id": { "type": "integer" },
                "orgId": { "type": ["string", "null"], "format": "uuid" },
                "actorUserId": { "type": ["string", "null"], "format": "uuid" },
                "actorLabel": { "type": ["string", "null"] },
                "action": { "type": "string", "examples": ["org.member.invited"] },
                "targetType": { "type": ["string", "null"] },
                "targetId": { "type": ["string", "null"] },
                "ip": { "type": ["string", "null"] },
                "userAgent": { "type": ["string", "null"] },
                "detail": { "type": "object" },
                "createdAt": timestamp,
            },
            "required": ["id", "action", "createdAt"],
        },
        "AuditEventList": { "type": "array", "items": reference("AuditEvent") },
    })
}

/// Wrappers the console reads back from an action.
fn response_schemas() -> Value {
    let role = json!({ "type": "string", "enum": ["owner", "admin", "member"] });

    json!({
        "Me": {
            "type": "object",
            "properties": {
                "user": reference("User"),
                "orgs": reference("MembershipList"),
                "shouldAddPasskey": { "type": "boolean" },
                "passkeyCount": { "type": "integer" },
                "credentialName": {
                    "type": "string",
                    "description":
                        "What a fresh registration would file this account's credential \
                         under. Send it back verbatim through \
                         PublicKeyCredential.signalCurrentUserDetails — composing it in \
                         the browser gives a second copy of a rule that will drift.",
                },
                "credentialDisplayName": { "type": "string" },
            },
            "required": [
                "user", "orgs", "shouldAddPasskey", "passkeyCount",
                "credentialName", "credentialDisplayName",
            ],
        },
        "Joined": {
            "type": "object",
            "properties": { "org": reference("Org"), "role": role },
            "required": ["org", "role"],
        },
        "SessionOpened": {
            "type": "object",
            "properties": {
                "user": reference("User"),
                "shouldAddPasskey": { "type": "boolean" },
            },
            "required": ["user", "shouldAddPasskey"],
        },
        "WebauthnConfig": {
            "type": "object",
            "description":
                "The relying party every passkey on this deployment is bound to.",
            "properties": {
                "rpId": {
                    "type": "string",
                    "description":
                        "Name this when signalling credential state. It is the origin's \
                         host or a registrable parent of it — not necessarily the host \
                         the console was served from.",
                },
            },
            "required": ["rpId"],
        },
        "RegistrationChallenge": {
            "type": "object",
            "description":
                "A WebAuthn creation challenge. Pass `challenge` to \
                 navigator.credentials.create() and send the result back with the \
                 same ceremonyId.",
            "properties": {
                "ceremonyId": { "type": "string", "format": "uuid" },
                "challenge": {
                    "type": "object",
                    "description": "PublicKeyCredentialCreationOptions, as the W3C defines it.",
                },
            },
            "required": ["ceremonyId", "challenge"],
        },
        "AuthenticationChallenge": {
            "type": "object",
            "description":
                "A WebAuthn request challenge. allowCredentials is empty: the \
                 credential the browser picks is what identifies the account.",
            "properties": {
                "ceremonyId": { "type": "string", "format": "uuid" },
                "challenge": {
                    "type": "object",
                    "description": "PublicKeyCredentialRequestOptions, as the W3C defines it.",
                },
            },
            "required": ["ceremonyId", "challenge"],
        },
        "Passkey": {
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "credentialId": {
                    "type": "string",
                    "description":
                        "The credential's own id, base64url without padding — what \
                         `signalAllAcceptedCredentials` matches a browser's stored \
                         credentials against.",
                },
                "nickname": { "type": ["string", "null"] },
                "createdAt": { "type": "string", "format": "date-time" },
                "lastUsedAt": { "type": ["string", "null"], "format": "date-time" },
            },
            "required": ["id", "credentialId", "nickname", "createdAt", "lastUsedAt"],
        },
        "PasskeyList": { "type": "array", "items": reference("Passkey") },
        "ClaimCode": {
            "type": "object",
            "description":
                "A one-time code letting an account register a passkey again. \
                 Returned once, to the admin who asked for it.",
            "properties": {
                "code": { "type": "string" },
                "link": { "type": "string" },
            },
            "required": ["code", "link"],
        },
        "CreatedInvite": {
            "type": "object",
            "description":
                "An invitation plus its one-time code, returned only from the call \
                 that mints it. Nothing is emailed; the admin delivers the code.",
            "allOf": [reference("Invite")],
            "properties": {
                "code": {
                    "type": "string",
                    "description": "The single-use code. Shown once — only its hash is stored.",
                },
                "link": {
                    "type": "string",
                    "description": "The same code as a console URL that redeems it.",
                },
            },
            "required": ["code", "link"],
        },
    })
}

/// Request bodies.
fn request_schemas() -> Value {
    let role = json!({ "type": "string", "enum": ["owner", "admin", "member"] });
    let locale = {
        let mut values: Vec<Value> = otto_core::i18n::SUPPORTED_LOCALES
            .iter()
            .map(|l| json!(l))
            .collect();
        values.push(Value::Null);
        json!({
            "type": ["string", "null"],
            "enum": values,
            "description": "Absent leaves the stored locale alone; a supported locale sets it; \
                null clears it back to following the browser's Accept-Language.",
        })
    };

    json!({
        "FinishRegistration": {
            "type": "object",
            "properties": {
                "ceremonyId": { "type": "string", "format": "uuid" },
                "credential": {
                    "type": "object",
                    "description": "The PublicKeyCredential from navigator.credentials.create().",
                },
                "nickname": { "type": ["string", "null"] },
            },
            "required": ["ceremonyId", "credential"],
        },
        "FinishAuthentication": {
            "type": "object",
            "properties": {
                "ceremonyId": { "type": "string", "format": "uuid" },
                "credential": {
                    "type": "object",
                    "description": "The PublicKeyCredential from navigator.credentials.get().",
                },
            },
            "required": ["ceremonyId", "credential"],
        },
        "ClaimRequest": {
            "type": "object",
            "properties": { "code": { "type": "string" } },
            "required": ["code"],
        },
        "FinishClaim": {
            "type": "object",
            "description": "The code is spent here, not at claim/start.",
            "properties": {
                "ceremonyId": { "type": "string", "format": "uuid" },
                "code": { "type": "string" },
                "credential": { "type": "object" },
                "nickname": { "type": ["string", "null"] },
            },
            "required": ["ceremonyId", "code", "credential"],
        },
        "ProfileRequest": {
            "type": "object",
            "properties": {
                "email": { "type": ["string", "null"], "format": "email" },
                "name": { "type": ["string", "null"] },
                "locale": locale,
            },
        },
        "RenameKeyRequest": {
            "type": "object",
            "properties": { "nickname": { "type": "string" } },
            "required": ["nickname"],
        },
        "CreateOrgRequest": {
            "type": "object",
            "properties": {
                "slug": { "type": "string" },
                "name": { "type": "string" },
            },
            "required": ["slug", "name"],
        },
        "RoleRequest": {
            "type": "object",
            "properties": { "role": role },
            "required": ["role"],
        },
        "InviteRequest": {
            "type": "object",
            "properties": {
                "email": { "type": "string", "format": "email" },
                "role": role,
            },
            "required": ["email"],
        },
        "AcceptInviteRequest": {
            "type": "object",
            "properties": { "token": { "type": "string" } },
            "required": ["token"],
        },
        "CreateTeamRequest": {
            "type": "object",
            "properties": {
                "slug": { "type": "string" },
                "name": { "type": ["string", "null"] },
            },
            "required": ["slug"],
        },
        "TeamPatch": {
            "type": "object",
            "description": "Absent fields are left alone.",
            "properties": {
                "slug": { "type": ["string", "null"] },
                "name": { "type": ["string", "null"] },
            },
        },
        "MintTokenRequest": {
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "resource": {
                    "type": ["string", "null"],
                    "description":
                        "The resource server's RFC 8707 resource URI. Optional only \
                         while exactly one resource server is registered.",
                },
                "scopes": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description":
                        "Scopes the resource server defines. Defaults to its default \
                         scopes when empty.",
                },
                "ttlDays": { "type": ["integer", "null"], "minimum": 1, "maximum": 365 },
            },
            "required": ["name"],
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Value {
        document(&catalog())
    }

    /// The drift test. Every schema the catalog names has to exist, or a
    /// generated client gets a dangling `$ref` and fails to build.
    #[test]
    fn every_referenced_schema_is_defined() {
        let doc = doc();
        let schemas = doc["components"]["schemas"].as_object().unwrap();

        let mut refs = Vec::new();
        collect_refs(&doc, &mut refs);

        for name in refs {
            assert!(
                schemas.contains_key(&name),
                "the document references #/components/schemas/{name}, which is not defined"
            );
        }
    }

    /// The inverse of the drift test above. `Enrollment`, `SignupRequest`,
    /// `LoginRequest` and `ConfirmTotpRequest` all outlived the TOTP-era
    /// flows that returned or took them, as dead documentation nothing
    /// caught — a hand-maintained document has no compiler to notice an
    /// endpoint stopped existing. A schema no `$ref` anywhere in the
    /// document names is exactly that: describing a shape the server no
    /// longer sends or accepts.
    #[test]
    fn every_defined_schema_is_referenced() {
        let doc = doc();
        let schemas = doc["components"]["schemas"].as_object().unwrap();

        let mut refs = Vec::new();
        collect_refs(&doc, &mut refs);
        let refs: std::collections::HashSet<_> = refs.into_iter().collect();

        for name in schemas.keys() {
            assert!(
                refs.contains(name),
                "components/schemas/{name} is defined but nothing $refs it \
                 anywhere in the document"
            );
        }
    }

    fn collect_refs(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    if key == "$ref" {
                        if let Some(name) = value.as_str().and_then(|r| {
                            r.strip_prefix("#/components/schemas/").map(str::to_string)
                        }) {
                            out.push(name);
                        }
                    }
                    collect_refs(value, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|v| collect_refs(v, out)),
            _ => {}
        }
    }

    /// An endpoint with no summary is an endpoint nobody outside this repo can
    /// use. Every route is public API, so every route gets a sentence.
    #[test]
    fn every_endpoint_describes_itself() {
        for endpoint in catalog() {
            assert!(
                !endpoint.summary.is_empty(),
                "{} {} has no summary",
                endpoint.verb.as_str(),
                endpoint.path
            );
        }
    }

    /// An endpoint that claims an org scope but has no `{org}` segment cannot
    /// resolve one — `OrgCtx` would fail at runtime with an internal error.
    /// This is the wiring bug that check exists to report.
    #[test]
    fn org_scoped_endpoints_sit_under_an_org_segment() {
        for endpoint in catalog() {
            if endpoint.auth.needs_org() {
                assert!(
                    endpoint.path_params().contains(&"org"),
                    "{} {} claims {} but has no {{org}} segment",
                    endpoint.verb.as_str(),
                    endpoint.path,
                    endpoint.auth.as_str()
                );
            }
        }
    }

    /// Operation ids become method names in generated clients, so a duplicate
    /// silently overwrites a method.
    #[test]
    fn operation_ids_are_unique() {
        let mut ids: Vec<String> = catalog().iter().map(|e| e.operation_id()).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate operationId in the catalog");
    }

    /// **The rule from the plan, as a test.** No credential is ever spent on a
    /// `GET`: link-preview fetchers follow every URL in every message, and a
    /// single-use `GET` is burned before the human ever clicks it — a failure
    /// that looks exactly like an attack and is not.
    ///
    /// The product sends no mail any more, which narrows the list but does not
    /// retire the rule: an invitation code now travels through Slack, a ticket,
    /// or a chat window, and every one of those unfurls links too.
    ///
    /// Named endpoints rather than a pattern match, because the property is
    /// about these specific redemptions. Moving one to `GET`, or deleting it,
    /// fails here.
    #[test]
    fn every_single_use_redemption_is_a_post() {
        let redemptions = [
            "/api/auth/signup/finish",
            "/api/auth/login/finish",
            "/api/auth/claim/finish",
            "/api/orgs/{org}/invites/accept",
            "/oauth/token",
        ];

        let catalog = catalog();
        for path in redemptions {
            let mounted: Vec<_> = catalog.iter().filter(|e| e.path == path).collect();
            assert!(!mounted.is_empty(), "{path} is not mounted at all");

            for endpoint in mounted {
                assert_eq!(
                    endpoint.verb,
                    crate::catalog::Verb::Post,
                    "{path} spends a single-use credential, so it must be a POST — \
                     mail scanners and link previews follow every URL they see"
                );
            }
        }
    }

    /// The other half: the page an invitation link points at is not a route
    /// here at all. `/invite/{org}` is a console page that renders a button; the
    /// server sees nothing until the button is pressed.
    ///
    /// `/verify` and `/recover` are listed too, and must stay absent for a
    /// different reason — they are gone. There is no email, so there is nothing
    /// to verify an address with and no recovery link to spend. Re-adding either
    /// as a route means somebody has quietly reintroduced a mailer.
    #[test]
    fn redeemable_urls_are_pages_not_endpoints() {
        for path in ["/invite/{org}", "/claim", "/verify", "/recover"] {
            assert!(
                !catalog().iter().any(|e| e.path == path),
                "{path} is a URL handed to a human. It must stay a client-side page — \
                 mounting it as a handler is how a link gets spent by a link preview."
            );
        }
    }

    #[test]
    fn the_document_is_openapi_31_with_a_session_scheme() {
        let doc = doc();
        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(
            doc["components"]["securitySchemes"]["sessionCookie"]["name"],
            crate::session::COOKIE_NAME
        );
        assert!(doc["paths"]["/api/me"]["get"]["security"].is_array());
        assert!(
            doc["paths"]["/api/auth/login/start"]["post"]
                .get("security")
                .is_none(),
            "a public endpoint must not require a session"
        );
    }

    /// One path serving several methods must render as one entry with several
    /// operations, not as the last one written.
    #[test]
    fn a_path_with_several_methods_keeps_all_of_them() {
        let doc = doc();
        let sessions = &doc["paths"]["/api/me/sessions"];
        assert!(sessions["get"].is_object(), "GET was lost");
        assert!(sessions["delete"].is_object(), "DELETE was lost");
    }
}
