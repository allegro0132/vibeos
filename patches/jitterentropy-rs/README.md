# jitterentropy-rs integration

`vendor/jitterentropy-rs` is the unmodified upstream Git submodule pinned to
commit `c5bd2e17194fe3a04d17f74027bb67622579405f` (crate 0.1.1).

`0001-vibeos-qualification.patch` adds the feature-gated raw-delta API used by
the qualification images and avoids an unused import warning on no-std RISC-V.
It does not change the production conditioned-output algorithm. Apply or verify
the patch with:

```sh
./scripts/prepare-jitterentropy-rs.sh
```

The preparation script is idempotent. A fresh checkout needs:

```sh
git submodule update --init vendor/jitterentropy-rs
./scripts/prepare-jitterentropy-rs.sh
```
