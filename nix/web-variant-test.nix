# THE `web` VARIANT, DRIVEN ACROSS A PAGE RELOAD.
#
# This module's whole job is to hold a key that nobody else can read and that
# the user does not lose. Inside a Wasm host both halves are at risk in a way
# they are not natively, and neither risk shows up in a build:
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
#     access out of bounds`. Every step below has to hold, in order, or this
#     module is not usable in a webview.
#
# TWO IMAGES IS THE POINT. A wasm instance owns its linear memory and shares
# none of it, so a second instantiation of the same glue is to a module's store
# exactly what the page after a reload is: the only path from the first image to
# the second is the durable medium.
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
  cp "$variant/keystore_module_wasm.js" ./host.js

  cat > drive.js <<'JS'
  // The Web container's job, done in node.
  const factory = require('./host.js');
  const fs = require('fs'), os = require('os'), path = require('path');
  const CALL = 1, RESULT = 2;
  const fail = (why, t) => { console.error('FAIL: ' + why); if (t) console.error(JSON.stringify(t, null, 2)); process.exit(1); };

  async function spawn(opts = {}) {
    const heard = []; let hello = null;
    const mod = await factory(Object.assign({
      logosOut: (t) => { let m; try { m = JSON.parse(t); } catch (e) { return; }
        if (m.logosWasmHost) { hello = m; return; } heard.push(m); },
      print: () => {}, printErr: (s) => console.error('[image] ' + s),
    }, opts));
    const deliver = mod.cwrap('logos_wasm_deliver', null, ['string']);
    return { heard, hello: () => hello,
      send: (id, method, args) => deliver(JSON.stringify({ type: CALL,
        payload: { id, authToken: "", object: 'keystore_module', method, args } })),
      result: (id) => heard.find((m) => m.type === RESULT && m.payload.id === id) };
  }

  const PW = 'correct horse battery staple';

  (async () => {
    const store = fs.mkdtempSync(path.join(os.tmpdir(), 'logos-keystore-web-'));

    // ── IMAGE A: create and encrypt ─────────────────────────────────────────
    const a = await spawn({ logosStorageHostDir: store });
    if (!a.hello() || a.hello().storage !== 'nodefs') {
      fail('the image mounted no durable store: ' + JSON.stringify(a.hello()));
    }
    a.send(1, 'new_account', [PW]);
    const made = a.result(1);
    if (!made || !made.payload.ok) fail('new_account did not answer', a.heard);
    const created = JSON.parse(made.payload.value);
    if (!created.ok || !created.address) fail('new_account: ' + made.payload.value);
    const addr = created.address;
    console.log('PASS: a `web` variant created and encrypted a key (' + addr + ')');

    // The vault reached the HOST filesystem, not just the image's view of one,
    // and it is a real scrypt keystore with no password in it.
    const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap(
      (e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
    const vault = walk(store).find(
      (f) => path.basename(f).toLowerCase().includes(addr.slice(2).toLowerCase()));
    if (!vault) fail('no vault reached the durable store: ' + JSON.stringify(walk(store)));
    const doc = JSON.parse(fs.readFileSync(vault, 'utf8'));
    if (!doc.crypto || doc.crypto.kdf !== 'scrypt') {
      fail('what reached the store is not a scrypt keystore: ' + JSON.stringify(doc).slice(0, 200));
    }
    if (JSON.stringify(doc).includes(PW)) fail('the password is in the stored vault');
    console.log('PASS: what crossed the barrier is a scrypt vault, with no password in it');

    // ── IMAGE B: the page after a reload ────────────────────────────────────
    const b = await spawn({ logosStorageHostDir: store });
    b.send(10, 'list_accounts', []);
    const listed = b.result(10);
    if (!listed || !listed.payload.ok) fail('list_accounts did not answer in the second image', b.heard);
    const accounts = JSON.parse(listed.payload.value).accounts || [];
    if (!accounts.map((x) => x.toLowerCase()).includes(addr.toLowerCase())) {
      fail('the second image does not see the key: ' + listed.payload.value);
    }
    console.log('PASS: a second image lists the key the first one created');

    // ...and it is a USABLE key, not merely a file that survived.
    b.send(11, 'unlock', [addr, PW]);
    const unlocked = b.result(11);
    if (!unlocked || unlocked.payload.value !== true) fail('the reloaded vault would not unlock', b.heard);
    b.send(12, 'sign_message', [addr, 'hello from the second image']);
    const signed = b.result(12);
    if (!signed || !signed.payload.ok) fail('signing with the reloaded key did not answer', b.heard);
    const sig = JSON.parse(signed.payload.value);
    if (!sig.ok || !/^0x[0-9a-fA-F]{130}$/.test(sig.signature)) {
      fail('sign_message: ' + signed.payload.value);
    }
    console.log('PASS: the second image unlocked the reloaded vault and signed with it');

    // ── and the vault is still a vault ──────────────────────────────────────
    b.send(13, 'unlock', [addr, 'wrong']);
    const bad = b.result(13);
    if (!bad || bad.payload.value !== false) fail('a wrong password unlocked the reloaded vault', b.heard);
    console.log('PASS: a wrong password is refused after the reload');

    // ── A DELETE IS A WRITE ─────────────────────────────────────────────────
    // Without a barrier behind it the vault is BACK in the next image, which is
    // worse than a lost write: the user deleted a key and it is still there.
    b.send(14, 'delete_account', [addr, PW]);
    const deleted = b.result(14);
    if (!deleted || deleted.payload.value !== true) fail('delete_account did not answer true', b.heard);
    const c = await spawn({ logosStorageHostDir: store });
    c.send(20, 'has_address', [addr]);
    const revived = c.result(20);
    if (!revived || revived.payload.value !== false) {
      fail('a deleted key came back in the next image -- the removal had no barrier', c.heard);
    }
    console.log('PASS: a deleted key stays deleted across a reload');
  })().catch((e) => fail('the harness threw: ' + (e && e.stack || e)));
JS

  node drive.js
  mkdir -p $out
  echo ok > $out/result
''
