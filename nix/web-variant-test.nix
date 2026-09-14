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
#     about any of it. Every step below has to hold, in order, or this module is
#     not usable in a webview.
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
  cp "$variant/keystore_module_wasm.js" ./host.js

  cat > drive.js <<'JS'
  // The Web container's job, done in node.
  const factory = require('./host.js');
  const fs = require('fs'), os = require('os'), path = require('path');
  const CALL = 1, RESULT = 2, TOKEN = 6;
  const fail = (why, t) => { console.error('FAIL: ' + why); if (t) console.error(JSON.stringify(t, null, 2)); process.exit(1); };

  // Three callers, each a name this image was TOLD about. The keystore resolves a
  // caller from the token a call presents, so a harness that wants to be admitted
  // as the custodian and refused as anyone else needs one token per identity.
  const CUSTODIAN = { name: 'keystore_custodian', token: 'tok-custodian' };
  const APPROVER  = { name: 'evm_signer_ui',      token: 'tok-approver'  };
  const REQUESTER = { name: 'eth_wallet_backend', token: 'tok-requester' };

  async function spawn(opts = {}) {
    const heard = []; let hello = null;
    const mod = await factory(Object.assign({
      logosOut: (t) => { let m; try { m = JSON.parse(t); } catch (e) { return; }
        if (m.logosWasmHost) { hello = m; return; } heard.push(m); },
      print: () => {}, printErr: (s) => console.error('[image] ' + s),
    }, opts));
    const deliver = mod.cwrap('logos_wasm_deliver', null, ['string']);
    let next = 0;
    const image = {
      heard, hello: () => hello,
      token: (who) => deliver(JSON.stringify({ type: TOKEN,
        payload: { authToken: "", moduleName: who.name, token: who.token } })),
      // Answers are synchronous on this transport: the image is driven on this
      // thread and the RESULT is already in `heard` when deliver() returns.
      call: (who, method, args) => {
        const id = ++next;
        deliver(JSON.stringify({ type: CALL,
          payload: { id, authToken: who.token, object: 'keystore_module', method, args } }));
        const res = heard.find((m) => m.type === RESULT && m.payload.id === id);
        if (!res) fail(method + ' did not answer at all', heard);
        if (!res.payload.ok) fail(method + ' failed at the transport: ' + res.payload.err, heard);
        return res.payload.value;
      },
      // Every structured reply is a JSON string. Parsed once, here.
      json: (who, method, args) => {
        const raw = image.call(who, method, args);
        try { return JSON.parse(raw); } catch (e) { fail(method + ' answered malformed JSON: ' + raw); }
      },
    };
    return image;
  }

  // Who this image says it is serving, so every gate assertion below means something.
  function identify(image, who) {
    const id = image.json(who, 'caller_identity', []);
    if (id.kind !== 'module' || id.identity !== who.name) {
      fail('the image does not see ' + who.name + ' as the caller: ' + JSON.stringify(id));
    }
  }

  // Total: the document is the whole answer to who holds the two roles, and it is
  // in memory — so the image after a reload has to be told again.
  function nameTheRoles(image) {
    const r = image.json(CUSTODIAN, 'configure',
      [JSON.stringify({ approvers: APPROVER.name, custodians: CUSTODIAN.name })]);
    if (!r.ok || r.custodians[0] !== CUSTODIAN.name || r.approvers[0] !== APPROVER.name) {
      fail('configure did not take: ' + JSON.stringify(r));
    }
  }

  const PW = 'correct horse battery staple';
  const TEXT = 'hello from the second image';

  (async () => {
    const store = fs.mkdtempSync(path.join(os.tmpdir(), 'logos-keystore-web-'));

    // ── IMAGE A: the custodian creates a key ────────────────────────────────
    const a = await spawn({ logosStorageHostDir: store });
    if (!a.hello() || a.hello().logosWasmHost !== 'keystore_module') {
      fail('the image did not announce itself: ' + JSON.stringify(a.hello()));
    }
    if (a.hello().storage !== 'nodefs') {
      fail('the image mounted no durable store: ' + JSON.stringify(a.hello()));
    }
    for (const who of [CUSTODIAN, APPROVER, REQUESTER]) a.token(who);
    identify(a, CUSTODIAN); identify(a, REQUESTER);
    nameTheRoles(a);
    console.log('PASS: the image resolves a caller per token, and takes its roles');

    // Tier D admits the custodian ALONE. A named module that is not it is refused
    // in the same words every other tier refuses in.
    const refused = a.json(REQUESTER, 'create_unrelated_account',
      [JSON.stringify({ password: PW, acknowledgeUnrecoverable: true })]);
    if (refused.ok !== false || refused.error !== 'not authorized') {
      fail('Tier D admitted a caller that is not the custodian: ' + JSON.stringify(refused));
    }

    // ...and the acknowledgement is a property of the CALL, not of the caller, so
    // the one identity Tier D admits does not skip it.
    const unacknowledged = a.json(CUSTODIAN, 'create_unrelated_account',
      [JSON.stringify({ password: PW, acknowledgeUnrecoverable: false })]);
    if (unacknowledged.ok !== false || !/recovery phrase will not restore/.test(unacknowledged.error)) {
      fail('an unrelated account was minted without the acknowledgement: ' + JSON.stringify(unacknowledged));
    }
    console.log('PASS: Tier D refuses everyone but the custodian, and the custodian without the acknowledgement');

    const created = a.json(CUSTODIAN, 'create_unrelated_account',
      [JSON.stringify({ password: PW, acknowledgeUnrecoverable: true })]);
    if (!created.ok || !created.address) fail('create_unrelated_account: ' + JSON.stringify(created));
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
    for (const who of [CUSTODIAN, APPROVER, REQUESTER]) b.token(who);
    nameTheRoles(b);

    const listed = b.json(REQUESTER, 'list_accounts', []);
    if (!listed.ok) fail('list_accounts did not answer in the second image: ' + JSON.stringify(listed));
    if (!(listed.accounts || []).map((x) => x.toLowerCase()).includes(addr.toLowerCase())) {
      fail('the second image does not see the key: ' + JSON.stringify(listed));
    }
    console.log('PASS: a second image lists the key the first one created');

    // ...and it is a USABLE key, not merely a file that survived. Signing is the
    // approved-signing flow end to end: a named module asks, the approver renders
    // and approves, and only the requester's receipt collects the signature.
    const asked = b.json(REQUESTER, 'request_approval', [JSON.stringify({
      address: addr, purpose: 'web-variant check',
      legs: [{ kind: 'message', text: TEXT }],
    })]);
    if (!asked.ok || !asked.handle || !asked.receipt) fail('request_approval: ' + JSON.stringify(asked));

    // Tier A is the approver alone — the requester cannot approve its own request.
    const selfApproved = b.json(REQUESTER, 'approve', [asked.handle, 'whatever', PW]);
    if (selfApproved.ok !== false || selfApproved.error !== 'not authorized') {
      fail('a requester approved its own request: ' + JSON.stringify(selfApproved));
    }

    const queue = b.json(APPROVER, 'pending', []);
    if (!queue.ok || !(queue.pending || []).some((p) => p.handle === asked.handle)) {
      fail('the approver does not see the request: ' + JSON.stringify(queue));
    }

    const shown = b.json(APPROVER, 'acknowledge', [asked.handle]);
    if (!shown.ok || !shown.bundle_id) fail('acknowledge: ' + JSON.stringify(shown));
    if (!shown.render_lines.join('\n').includes(TEXT)) {
      fail('what the human would read is not what was asked for: ' + JSON.stringify(shown.render_lines));
    }

    // A wrong password does not settle the request — the human retries.
    const wrong = b.json(APPROVER, 'approve', [asked.handle, shown.bundle_id, 'wrong']);
    if (wrong.ok !== false) fail('a wrong password signed after the reload: ' + JSON.stringify(wrong));

    const approved = b.json(APPROVER, 'approve', [asked.handle, shown.bundle_id, PW]);
    if (!approved.ok || approved.signed_count !== 1) fail('approve: ' + JSON.stringify(approved));

    const collected = b.json(REQUESTER, 'fetch_result', [asked.handle, asked.receipt]);
    if (!collected.ok || !Array.isArray(collected.signed) || collected.signed.length !== 1) {
      fail('fetch_result: ' + JSON.stringify(collected));
    }
    if (!/^0x[0-9a-fA-F]{130}$/.test(collected.signed[0])) {
      fail('what came back is not a secp256k1 signature: ' + JSON.stringify(collected.signed));
    }
    console.log('PASS: the reloaded vault signed, through the approval flow, in wasm');

    const acked = b.call(REQUESTER, 'ack_result', [asked.handle, asked.receipt]);
    if (acked !== true) fail('ack_result did not answer true: ' + JSON.stringify(acked));
    const gone = b.json(REQUESTER, 'fetch_result', [asked.handle, asked.receipt]);
    if (gone.ok !== false) fail('the signatures survived the ack: ' + JSON.stringify(gone));
    console.log('PASS: the signatures are erased once the requester has them');

    // ── A DELETE IS A WRITE ─────────────────────────────────────────────────
    // Without a barrier behind it the vault is BACK in the next image, which is
    // worse than a lost write: the user deleted a key and it is still there.
    const deleted = b.call(CUSTODIAN, 'delete_account', [addr, PW]);
    if (deleted !== true) fail('delete_account did not answer true: ' + JSON.stringify(deleted));
    const c = await spawn({ logosStorageHostDir: store });
    for (const who of [CUSTODIAN, APPROVER, REQUESTER]) c.token(who);
    const revived = c.call(REQUESTER, 'has_address', [addr]);
    if (revived !== false) {
      fail('a deleted key came back in the next image -- the removal had no barrier', c.heard);
    }
    console.log('PASS: a deleted key stays deleted across a reload');
  })().catch((e) => fail('the harness threw: ' + (e && e.stack || e)));
  JS

  node drive.js
  mkdir -p $out
  echo ok > $out/result
''
