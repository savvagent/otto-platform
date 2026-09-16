//! The locales the identity/console layer is translated into.
//!
//! Not part of this extraction's explicit file list, but pulled in as a
//! dependency of [`crate::orgs::Db::set_profile`], which validates a chosen
//! locale against [`SUPPORTED_LOCALES`] before storing it on `users.locale`.
//! See this crate's top-level docs for why `users` carries no `CHECK`
//! constraint for this instead.
//!
//! The original `of_core::i18n` also asserted, in a test, that this list
//! agreed with a sibling SvelteKit console's `project.inlang/settings.json`.
//! That console (`of-web`/`web/`) is not part of this extraction — otto-flags'
//! design doc defers the shared Otto Console to its own future work — so
//! that drift-guard test has no file to check against here and is not carried
//! over. Re-add it once a console lives in this repo or a sibling one.

use otto_tenant::Error;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Every locale the identity layer is translated into.
///
/// Ordered `en` first because it is the base and the fallback.
pub const SUPPORTED_LOCALES: [&str; 6] = ["en", "es", "de", "fr", "it", "hi"];

/// One of [`SUPPORTED_LOCALES`], parsed.
///
/// Bare language subtags, not region-qualified: a region variant (`es-419`,
/// `pt-BR`) would be a new locale file rather than a rework of this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    /// The base locale, and the fallback for anything unresolvable.
    #[default]
    En,
    Es,
    De,
    Fr,
    It,
    Hi,
}

impl Locale {
    /// In the same order as [`SUPPORTED_LOCALES`], which a test pins.
    pub const ALL: [Locale; 6] = [
        Locale::En,
        Locale::Es,
        Locale::De,
        Locale::Fr,
        Locale::It,
        Locale::Hi,
    ];

    /// The BCP 47 subtag — what goes in `<html lang>` and in `users.locale`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Es => "es",
            Locale::De => "de",
            Locale::Fr => "fr",
            Locale::It => "it",
            Locale::Hi => "hi",
        }
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Locale {
    type Err = Error;

    /// Case-insensitive, and a region subtag resolves to its language.
    ///
    /// `es-419` and `es-MX` are Spanish. Refusing them would mean a browser
    /// that quite correctly sends a region gets English instead, which is the
    /// opposite of the point.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let primary = s.split(['-', '_']).next().unwrap_or_default();
        let primary = primary.trim().to_ascii_lowercase();

        Locale::ALL
            .into_iter()
            .find(|l| l.as_str() == primary)
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "{s:?} is not a supported locale; use one of: {}",
                    SUPPORTED_LOCALES.join(", ")
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_enum_and_the_string_list_are_the_same_list() {
        let from_enum: Vec<&str> = Locale::ALL.iter().map(|l| l.as_str()).collect();
        assert_eq!(from_enum, SUPPORTED_LOCALES.to_vec());
    }

    #[test]
    fn a_region_subtag_resolves_to_its_language() {
        for tag in ["es-419", "es_MX", "ES-mx", "de-CH", "hi-IN"] {
            assert!(tag.parse::<Locale>().is_ok(), "{tag} should parse");
        }
        assert_eq!("es-419".parse::<Locale>().unwrap(), Locale::Es);
        assert_eq!("DE".parse::<Locale>().unwrap(), Locale::De);
    }

    /// The house rule for errors: say what was wrong *and* what would work.
    #[test]
    fn an_unsupported_locale_names_the_supported_ones() {
        let err = "klingon".parse::<Locale>().unwrap_err().to_string();
        for locale in SUPPORTED_LOCALES {
            assert!(err.contains(locale), "{err:?} should name {locale}");
        }
    }

    #[test]
    fn nothing_parses_to_a_locale_by_accident() {
        for junk in ["", "  ", "-", "zz", "english", "e"] {
            assert!(junk.parse::<Locale>().is_err(), "{junk:?} should not parse");
        }
    }
}
