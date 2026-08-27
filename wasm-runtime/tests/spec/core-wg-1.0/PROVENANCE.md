# WebAssembly Core fixture provenance

This directory vendors an unmodified, narrowly selected fixture from the
official WebAssembly specification test suite. It is test input, not a claim of
full Core conformance.

## Immutable upstream pin

- Repository: <https://github.com/WebAssembly/spec>
- Human-readable tag: `wg-1.0`
- Commit: `977f97014c962f7bd1291fcc6d28b41a924882bf`
- Upstream suite description: the pinned
  [`test/README.md`](https://github.com/WebAssembly/spec/blob/977f97014c962f7bd1291fcc6d28b41a924882bf/test/README.md)
  identifies `test/core/` as tests for the core semantics.

The tag-to-commit mapping was verified directly against the official Git
remote. The commit hash, rather than the movable local tag name, is the
authority used by this repository.

## Vendored bytes

| Local file | Pinned upstream path | Bytes | Git blob | SHA-256 |
| --- | --- | ---: | --- | --- |
| `fac.wast` | [`test/core/fac.wast`](https://github.com/WebAssembly/spec/blob/977f97014c962f7bd1291fcc6d28b41a924882bf/test/core/fac.wast) | 2602 | `ef10991a82c0fc3113fa4567d7dbdc2791f14bc8` | `7bf27b090f6533865acc79a37e0331b27fa11d7a3ab27b02e32e2efddfb405e7` |
| `LICENSE` | [`test/LICENSE`](https://github.com/WebAssembly/spec/blob/977f97014c962f7bd1291fcc6d28b41a924882bf/test/LICENSE) | 11358 | `8f71f43fee3f78649d238238cbde51e6d7055c82` | `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08` |

Raw-byte download URLs are pinned to the same commit:

- <https://raw.githubusercontent.com/WebAssembly/spec/977f97014c962f7bd1291fcc6d28b41a924882bf/test/core/fac.wast>
- <https://raw.githubusercontent.com/WebAssembly/spec/977f97014c962f7bd1291fcc6d28b41a924882bf/test/LICENSE>

The upstream root [`LICENSE`](https://github.com/WebAssembly/spec/blob/977f97014c962f7bd1291fcc6d28b41a924882bf/LICENSE)
assigns `test/` to Apache License 2.0. The exact pinned `test/LICENSE` bytes are
included beside the fixture.

## Selection and scope

The complete pinned `fac.wast` contains one anonymous module, five
`assert_return` directives, and one `assert_exhaustion` directive. It exercises
integer calls, recursion, locals, blocks, loops, branches, and exact call-stack
exhaustion while remaining inside VibeOS Profile 1.

The newer official `v1.0.0` (`d910f03bd6d6477656fc5070b5098e8f909305d3`)
and `wg-2.0` (`fffc6e12fa454e475455a7b58d3b5dc343980c10`) versions of
this same fixture add `fac-ssa`, multi-value function results, and a typed loop.
Profile 1 intentionally disables multi-value, so either newer file would be
rejected as a whole before reaching the selected integer semantic assertions.
Using the complete `wg-1.0` file avoids modifying upstream test bytes or
silently weakening Profile 1.

This evidence therefore closes only the selected Core 1.0 integer semantic
baseline required by roadmap node C1.6. It does not claim execution of the full
official test suite, Core 2.0 conformance, or fuzz coverage (C1.7).

## Update policy

An update must pin a new immutable upstream commit, vendor complete unmodified
files with their applicable license, refresh every byte count/blob/SHA-256 pin,
and explicitly review every WAST directive against the current Profile 1
feature policy. The offline Rust test must fail closed on unknown directives or
value kinds; no directive may be skipped to make an updated fixture pass.
