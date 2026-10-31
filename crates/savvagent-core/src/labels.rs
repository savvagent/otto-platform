//! The generated handle that names one account in a credential vault.

use rand::Rng;

/// A fresh `adjective-noun-NN` handle, e.g. `brisk-harbor-42`.
///
/// **Random, never derived from the account id.** A label computed as a
/// function of the primary key would let anybody who learned an id — from a URL,
/// an audit entry, a support thread — recover the words the account's passkey is
/// filed under, and a label is shown in places an id is not. Drawing it makes
/// the two facts independent; 80 x 80 x 90 is ample for telling apart the
/// handful of accounts one person holds, which is the entire job.
///
/// **Always English, in every locale.** The label is a handle, not prose: it is
/// stored once, shown by the operating system's credential picker, and read back
/// by a human comparing it against the console. Translating it would make the
/// picker and the console disagree for the same account — and would change the
/// stored words the day somebody switched languages.
///
/// Collisions are cosmetic and deliberately not prevented: `users.label` carries
/// no unique index, because a duplicate must never turn into a failed signup.
pub fn generate() -> String {
    let mut rng = rand::thread_rng();
    let adjective = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    let number: u32 = rng.gen_range(10..=99);
    format!("{adjective}-{noun}-{number}")
}

/// Short, unambiguous, and spellable out loud over a phone call — the label
/// gets read back by a human at least as often as it gets clicked.
const ADJECTIVES: [&str; 80] = [
    "amber", "ancient", "arctic", "autumn", "azure", "balmy", "bold", "boreal", "brave", "breezy",
    "bright", "brisk", "bronze", "calm", "candid", "cheerful", "civic", "clear", "clever",
    "cobalt", "cosmic", "crimson", "crisp", "curious", "daring", "dazzling", "deft", "dewy",
    "distant", "eager", "early", "earnest", "easy", "electric", "elegant", "ember", "emerald",
    "fabled", "fearless", "fleet", "fluent", "frosty", "gallant", "gentle", "gilded", "glad",
    "gleaming", "golden", "graceful", "grand", "hardy", "hidden", "humble", "indigo", "jolly",
    "keen", "kindly", "lively", "lucid", "lunar", "marble", "merry", "mighty", "mellow", "misty",
    "modest", "noble", "nimble", "opal", "patient", "placid", "plucky", "polar", "prime", "quiet",
    "rapid", "restless", "rugged", "sable", "serene",
];

const NOUNS: [&str; 80] = [
    "acorn", "anchor", "arbor", "arrow", "aspen", "badger", "basin", "beacon", "birch", "bison",
    "bramble", "breeze", "brook", "canyon", "cedar", "cinder", "clover", "comet", "compass",
    "coral", "cove", "crane", "crest", "cypress", "delta", "dune", "eagle", "elder", "falcon",
    "fern", "fjord", "forge", "gale", "garnet", "glacier", "glade", "granite", "grove", "harbor",
    "harvest", "heron", "hollow", "horizon", "ivy", "juniper", "kestrel", "lagoon", "lantern",
    "ledger", "lichen", "lily", "lupine", "maple", "meadow", "mesa", "meteor", "moss", "nebula",
    "oak", "orchard", "otter", "pebble", "pine", "prairie", "quarry", "quill", "raven", "ridge",
    "river", "sequoia", "shale", "sparrow", "spruce", "summit", "thicket", "thistle", "tundra",
    "valley", "willow", "wren",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn a_label_is_two_words_and_two_digits() {
        let shape = regex::Regex::new("^[a-z]+-[a-z]+-[0-9]{2}$").expect("valid pattern");
        for _ in 0..1_000 {
            let label = generate();
            assert!(shape.is_match(&label), "{label:?} is not adjective-noun-NN");
        }
    }

    #[test]
    fn labels_spread_across_the_space() {
        // The failure that matters is a generator collapsed toward a constant —
        // a seed fixed once, an index that is always zero — which is exactly the
        // bug this change exists to fix, reintroduced one layer down. Asserting
        // that *two* draws differ would instead be a 1-in-576,000 flake.
        let drawn: HashSet<String> = (0..1_000).map(|_| generate()).collect();
        assert!(
            drawn.len() > 900,
            "only {} distinct labels in 1000",
            drawn.len()
        );
    }
}
