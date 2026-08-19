# Mutation log

A green suite proves nothing on its own. Each mutation below was introduced
deliberately and observed to fail the named test. Re-run this list after any
change to the tree, the invariant checker, or the property harness.

| # | Mutation | Failing test | Message |
|---|---|---|---|
| A | `overflow`: `<=` becomes `<` | **none — suite stays green** | 59/59 unit tests pass, 5/5 smoke tests pass. `children.len() < MAX_CHILDREN` splits one entry earlier than necessary, but `half = children.len() / 2` still lands both halves at or above `MAX_CHILDREN / 2 >= MIN_CHILDREN` (guaranteed by the crate's compile-time assert), so no tree the mutation produces is actually illegal. This is the predicted gap: `check_invariants`' `MIN_CHILDREN` branch has no test that exercises it, because no test tree is deep enough to contain a non-root internal node below the minimum. |
| B | `with_child_mut`: no `Arc::make_mut` | `insert_api_tests::editing_a_clone_leaves_the_original_alone` (14 tests failed total, including `proptests::rope_matches_the_model`) | `thread 'insert_api_tests::editing_a_clone_leaves_the_original_alone' panicked at crates/bropey/src/tree/children.rs:92:54: aliased` — the `.expect("aliased")` panic. All 14 failures, including the property harness, fail on this identical panic message; none fail on a snapshot-mismatch assertion. |
| C | `with_child_mut`: no size writeback | `tree::children::tests::with_child_mut_refreshes_the_cached_size` (20 tests failed total, including `proptests::rope_matches_the_model`) | `thread 'tree::children::tests::with_child_mut_refreshes_the_cached_size' panicked at crates/bropey/src/tree/children.rs:206:9: assertion `left == right` failed: cached size must follow the mutation / left: 3 / right: 6`. Every other failure (e.g. `composition_tests::a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one`) fails one level later, inside `check_invariants`, with the brief's predicted text: `assertion `left == right` failed: cached size 15 disagrees with subtree length 10 at child 2`. |
| D | `append`: no small-piece route | `tree::append::tests::an_underfull_side_is_absorbed_not_left_standing`, `tree::append::tests::repeated_small_appends_do_not_degenerate_the_tree`, `composition_tests::repeated_single_byte_removals_keep_the_tree_legal` (16 tests failed total, including `proptests::rope_matches_the_model`) | All three named tests fail identically, via `check_invariants`: `thread '...' panicked at crates/bropey/src/tree/invariants.rs:23:17: non-root leaf of N bytes is below MIN_BYTES 7` (N was 1, 1, and 6 respectively across the three). All three of the brief's named tests failed — none is weaker than intended. |
| E | `locate_insert`: `<=` becomes `<` | `tree::children::tests::locate_insert_biases_left_at_a_boundary` (18 tests failed total, including `proptests::rope_matches_the_model`) | `thread 'tree::children::tests::locate_insert_biases_left_at_a_boundary' panicked at crates/bropey/src/tree/children.rs:181:9: assertion `left == right` failed / left: (1, 0) / right: (0, 5)`. A named unit test localises the bug directly, as intended — not only the property test. |
| F | `insert`: always take the direct path | `composition_tests::a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one` and `proptests::rope_matches_the_model` (2 tests failed) | `thread 'composition_tests::a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one' panicked at crates/bropey/src/tree/mod.rs:64:9: direct insert of 60 bytes exceeds MAX_BYTES 15` — the `debug_assert!` in `Node::insert` fires, confirming it is load-bearing rather than decorative. |

## Notes on individual mutations

**Mutation A is an open finding, not a gap that was closed here.** Flipping
`overflow`'s comparison from `<=` to `<` makes the tree split one entry
before it strictly needs to, but every split it produces is still legal
under `MIN_CHILDREN`/`MAX_CHILDREN`, so the mutation is behaviourally inert
as far as every test in the suite (including `check_invariants` and the
property harness) can tell. This confirms, by direct construction, the
documented weakness: nothing in the suite builds a non-root internal node
close enough to `MIN_CHILDREN` to make this comparison matter. Closing it
needs a new test that forces a deep, narrow tree — deliberately constructed
rather than grown by `append`/`insert`'s balancing, since neither produces
node counts near the boundary in ordinary use — and checks the split
point of an internal node against both bounds. No such test was added;
this is reported for a scope decision rather than papered over.

**Mutation B proves detection-by-panic only, not detection-by-snapshot.**
The corrected mutation replaces `Arc::make_mut` with
`Arc::get_mut(...).expect("aliased")`. Every one of the 14 failures —
`editing_a_clone_leaves_the_original_alone`, the property harness, and 12
others — fails on the identical `"aliased"` panic from the `.expect()`, not
on a later content or snapshot mismatch. That is expected and is as far as
this can be pushed: the crate has zero `unsafe` and no interior mutability,
so a shared `Arc<Node>` cannot be mutated in place at all — silent aliasing
corruption is not expressible in this crate, only a loud panic is. The
aliasing tests exist as a regression guard on that invariant, not as a
demonstrated catch of silent corruption; they cannot fail today because the
type system rules out the case they would need to catch.

## Mutation C: which test localises, which test discovers

The most specific failure is the unit test `with_child_mut_refreshes_the_cached_size`,
which asserts the cached size directly at the point of mutation. Every
other failing test (the 19 others) instead trips `check_invariants`'s
`"cached size N disagrees with subtree length M at child I"` assertion one
level later — including `composition_tests::a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one`,
which is the first alphabetically. Both messages are recorded above.

## Working tree

All six mutations were applied one at a time, run under
`cargo test -p bropey`, and reverted with `git checkout` before the next.
Every `proptest-regressions/` file produced by a deliberately broken
mutation (Mutations B through F all produced one) was deleted before
moving on — those seeds record artificial failures, not real regressions.
The working tree is clean of all six mutations; only this file is new.
