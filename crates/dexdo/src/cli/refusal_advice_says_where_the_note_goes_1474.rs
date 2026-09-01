//! second point: the money-lock advice must say WHERE the note goes, not only which command.

//! The refusal shipped as `Run `dexdo orders journal` -- it shows that submission...`. The command
//! was right and the operator still could not run it: `--note-addr` belongs to the `orders` GROUP,
//! not to the `journal` subcommand, so an operator who appends it where it reads naturally --
//! after the subcommand -- meets a second refusal that names the flag without naming its position.
//! Two refusals to learn one word order.

//! # Why these assertions are tokens and not the sentence

//! `render()` is one of the four surfaces whose output is wrapped, and what it wraps is `do_next` --
//! this very advice. Width comes from the terminal with a ceiling of 120, and 120 is also used when
//! there is no terminal at all, so a pipe and a file wrap exactly like a screen. That leaves
//! 120 - 12 = 108 columns for the value, and every continuation line carries a 12-space prefix.

//! Words are not broken, but the gaps BETWEEN them are exactly where the break goes. So any
//! multi-word fragment can straddle a line and stop being found by `contains`, while every
//! space-free token survives untouched wherever the break lands. Asserting the whole sentence would
//! therefore pass today and fail the day the advice grows past 108 columns -- red for a reason that
//! has nothing to do with what this test is about.

//! Normalising the wrap away and asserting the joined sentence would also survive, and is worse:
//! it would check a string the operator never sees. The subject here is that the advice can be
//! READ OFF THE SCREEN and acted on, so the check stays on what the screen really carries.

//! # What this test deliberately does NOT assert

//! That the advice can be copied as one line. It cannot, once it exceeds 108 columns -- the wrap
//! splits it and the 12-space prefixes come with it. This PR makes the advice EXPLICABLE, not
//! copyable; requiring copyability here would be a red that names a defect this change never
//! claimed to fix.

use super::for_operator;

/// The flattened error the money-lock site really produces, taken from the case already pinned in
/// `refusal.rs` rather than composed here, so this test reads the same input the branch receives.
const MONEY_LOCK_HELD: &str = "buyer note 0000...0004::ad6f already has another money submission \
     awaiting by-fact reconciliation; no BOC was sent (/path/note.money: pool lock is already held)";

fn advice_for(message: &str) -> String {
    let refusal = for_operator(&anyhow::anyhow!(message.to_string()))
        .expect("the money-lock error is one the operator floor recognises");
    refusal.render()
}

/// The flag and the group it belongs to are both named, so the word order is derivable from the
/// sentence instead of from a second refusal.
#[test]
fn the_money_lock_advice_names_the_flag_and_the_group_it_belongs_to() {
    let rendered = advice_for(MONEY_LOCK_HELD);

    // `--note-addr` is one token: whatever the wrap does, it is either on a line or the advice
    // never named it. Before's second point the advice named no flag at all.
    assert!(
        rendered.contains("--note-addr"),
        "the advice must name the flag the operator has to add: {rendered}"
    );
    assert!(
        rendered.contains("orders"),
        "and the group that flag belongs to: {rendered}"
    );
    assert!(
        rendered.contains("subcommand"),
        "and it must say where that puts it relative to the subcommand: {rendered}"
    );
}

/// A second refusal exists for exactly this mistake, and the point of the fix is not to reach it.

/// Pinned as a token because it is the one word that distinguishes "the flag goes before the
/// subcommand" from a sentence that merely mentions both.
#[test]
fn the_advice_says_the_flag_comes_before_the_subcommand() {
    let rendered = advice_for(MONEY_LOCK_HELD);
    assert!(
        rendered.contains("before"),
        "position is the whole of the second point: naming the flag without naming where it goes \
         is the refusal this replaces: {rendered}"
    );
}

/// The first point of, kept from regressing while the second is fixed: an advice line that
/// carries an angle-bracket placeholder reads as runnable and is not.
#[test]
fn the_advice_hands_over_no_placeholder_to_fill_in() {
    let rendered = advice_for(MONEY_LOCK_HELD);
    assert!(
        !rendered.contains('<') && !rendered.contains('>'),
        "a placeholder is a line that looks copyable and is not; the command is NAMED instead: \
         {rendered}"
    );
}
