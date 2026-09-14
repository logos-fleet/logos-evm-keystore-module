// The Web container's job, done in node. `nix/web-variant-test.nix` builds the `web`
// variant, puts this file beside its wasm host and runs it; the header there says what
// this asserts and why it takes more than one image to ask.
'use strict';

const factory = require('./host.js');
const fs = require('fs'), os = require('os'), path = require('path');

const CALL = 1, RESULT = 2, TOKEN = 6;

const fail = (why, heard) => {
  console.error('FAIL: ' + why);
  if (heard) console.error(JSON.stringify(heard, null, 2));
  process.exit(1);
};

// Three callers, each a name this image was TOLD about. The keystore resolves a
// caller from the token a call presents, so a harness that wants to be admitted
// as the custodian and refused as anyone else needs one token per identity.
const CUSTODIAN = { name: 'keystore_custodian', token: 'tok-custodian' };
const APPROVER  = { name: 'evm_signer_ui',      token: 'tok-approver'  };
const REQUESTER = { name: 'eth_wallet_backend', token: 'tok-requester' };
const CALLERS = [CUSTODIAN, APPROVER, REQUESTER];

const PW = 'correct horse battery staple';
const TEXT = 'hello from the second image';

// One instantiation of the glue over `store`, with the three callers above already
// known to it. Calling this again is the page after a reload: a wasm instance shares
// none of its linear memory, so the only path from one image to the next is `store`.
async function spawn(store) {
  const heard = [];
  let hello = null;
  const mod = await factory({
    logosOut: (text) => {
      let msg;
      try { msg = JSON.parse(text); } catch { return; }
      if (msg.logosWasmHost) hello = msg; else heard.push(msg);
    },
    print: () => {},
    printErr: (s) => console.error('[image] ' + s),
    logosStorageHostDir: store,
  });
  const deliver = mod.cwrap('logos_wasm_deliver', null, ['string']);
  let next = 0;

  const image = {
    heard,
    hello: () => hello,
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
      try { return JSON.parse(raw); } catch { fail(method + ' answered malformed JSON: ' + raw); }
    },
  };

  for (const who of CALLERS) {
    deliver(JSON.stringify({ type: TOKEN,
      payload: { authToken: '', moduleName: who.name, token: who.token } }));
  }
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

// Every file under `dir`, so what reached the HOST filesystem can be asserted on
// rather than the image's view of one.
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap(
  (e) => e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);

(async () => {
  const store = fs.mkdtempSync(path.join(os.tmpdir(), 'logos-keystore-web-'));

  // ── IMAGE A: the custodian creates a key ────────────────────────────────
  const a = await spawn(store);
  if (!a.hello() || a.hello().logosWasmHost !== 'keystore_module') {
    fail('the image did not announce itself: ' + JSON.stringify(a.hello()));
  }
  if (a.hello().storage !== 'nodefs') {
    fail('the image mounted no durable store: ' + JSON.stringify(a.hello()));
  }
  identify(a, CUSTODIAN);
  identify(a, REQUESTER);
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
  const b = await spawn(store);
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

  const c = await spawn(store);
  const revived = c.call(REQUESTER, 'has_address', [addr]);
  if (revived !== false) {
    fail('a deleted key came back in the next image -- the removal had no barrier', c.heard);
  }
  console.log('PASS: a deleted key stays deleted across a reload');
})().catch((e) => fail('the harness threw: ' + (e?.stack ?? e)));
