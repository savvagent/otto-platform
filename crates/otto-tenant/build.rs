// `sqlx::migrate!` embeds `migrations/` at compile time, but cargo cannot see
// that dependency on stable Rust. Without this, adding a migration leaves the
// old schema compiled in until `cargo clean -p otto-tenant`.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
