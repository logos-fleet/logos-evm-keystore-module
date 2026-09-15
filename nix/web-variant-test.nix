# THE `web` VARIANT, DRIVEN ACROSS A PAGE RELOAD.
#
# This module's whole job is to hold a key that nobody else can read and that
# the user does not lose. Inside a Wasm host both halves are at risk in a way
# they are not natively, and none of the risks shows up in a build:
#
#   * an emscripten image HAS a filesystem, so a vault written with the ordinary
#     language runtime is written, read back correctly for the life of the page,
#     and GONE on the next load — with no error anywhere and nothing in the
#     module able to tell. That is what `logos_rust_sdk::storage`'s `commit()`
#     barrier exists for, and asserting it needs two images;
#   * the crypto has to actually run. It does not, by default: k256's ECDSA
#     signing overflows emscripten's 64 KB stack, so a `web` variant built
#     before logos-module-builder raised `-sSTACK_SIZE` created a key, stored it,
#     reloaded it — and died on the first signature with `RuntimeError: memory
#     access out of bounds`;
#   * and the ordinary file primitives are not all there. `File::try_lock` is
#     `Unsupported` on this target, and the keystore takes that lock for every
#     bookkeeping write — so before the fix this check landed with, the vault was
#     written and the provenance record was not, and `create_unrelated_account`
#     refused on a keystore that had just taken the key. A build says nothing
#     about any of it. Every step of the drive has to hold, in order, or this
#     module is not usable in a webview.
#
# IMPORTING IS ITS OWN CLAIM, and one nothing here made until
# logos-workspace#147. Creating a key needs a random number and scrypt; taking
# one FROM A SEED PHRASE needs BIP-39 and BIP-32 as well, and a wasm build can be
# subtly wrong there rather than absent — so the drive imports a known phrase and
# insists on the known address, then names the account, because on a phone the
# wallet has no store of its own to keep a label in. #147 was that wallet
# refusing the import as "keystore_module has no mobile build" while this image
# was loaded and answering; the question it raised was answerable only here.
#
# WHAT DOES THE DRIVING is `web-variant-drive.js` beside this file: the Web
# container's job, done in node. This derivation only builds the variant, puts
# the two beside each other and runs them.
#
# WHO IS CALLING IS PART OF WHAT IS ASSERTED. Account mutation is Tier D — the
# configured custodian alone — and signing is the approval flow, which needs a
# named requester and a named approver. The harness is the HOST here, presenting
# one token per identity, which is also why it is not affected by a `web`
# module's caller identity currently resolving to its own name (#129): nothing
# in this check is a second `web` module.
#
# TWO IMAGES IS THE POINT. A wasm instance owns its linear memory and shares
# none of it, so a second instantiation of the same glue is to a module's store
# exactly what the page after a reload is: the only path from the first image to
# the second is the durable medium. The roles are NOT on that path — `configure`
# is in-memory and total — so each image is told them again, which is itself the
# contract a container has to honour.
#
# NODEFS stands in for IndexedDB. The mount, the populate-before-main, the
# persistence path on the module context and the `logos_storage_commit` the
# barrier calls are one code path in logos-module-builder's Wasm host with the
# backend chosen at the bottom of it; what a browser would add here is a test of
# IndexedDB, not of this module.
{ pkgs, webVariant }:

pkgs.runCommand "keystore-web-variant-tests" {
  nativeBuildInputs = [ pkgs.nodejs ];
} ''
  set -euo pipefail
  variant=${webVariant}/keystore_module_web
  test -s "$variant/keystore_module_wasm.js" || { echo "FAIL: no wasm host in the web variant"; exit 1; }

  # Side by side in the build directory: the harness requires the host by relative
  # path, and node resolves that against the SCRIPT's own directory.
  cp "$variant/keystore_module_wasm.js" ./host.js
  cp ${./web-variant-drive.js} ./drive.js

  node drive.js
  mkdir -p $out
  echo ok > $out/result
''
