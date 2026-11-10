import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, finalizeEvent } from 'nostr-crypto-utils';
import { verifyNip98 } from '../examples/node/verify-nip98.mjs';

const URL = 'https://example.com/api/auth/nostr';
const NOW = Math.floor(Date.now() / 1000);

async function header(overrides = {}, tags = [['u', URL], ['method', 'POST']]) {
    const keys = await generateKeyPair();
    const event = await finalizeEvent({ kind: 27235, created_at: NOW, tags, content: '', ...overrides }, keys.privateKey);
    return { keys, event, h: 'Nostr ' + Buffer.from(JSON.stringify(event)).toString('base64') };
}
const enc = (e) => 'Nostr ' + Buffer.from(JSON.stringify(e)).toString('base64');

test('accepts a valid event once, then refuses a replay', async () => {
    const { keys, h } = await header();
    assert.equal(verifyNip98(h, URL, 'POST', NOW), keys.publicKey.hex);
    assert.throws(() => verifyNip98(h, URL, 'POST', NOW), /already used/);
});

test('refuses tampered content', async () => {
    const { event } = await header();
    assert.throws(() => verifyNip98(enc({ ...event, content: 'x' }), URL, 'POST', NOW), /bad signature/);
});

test('refuses another key claiming the signature', async () => {
    const { event } = await header();
    const other = await generateKeyPair();
    assert.throws(() => verifyNip98(enc({ ...event, pubkey: other.publicKey.hex }), URL, 'POST', NOW), /bad signature/);
});

test('refuses wrong url, method, kind and time', async () => {
    const a = await header();
    assert.throws(() => verifyNip98(a.h, URL + '/other', 'POST', NOW), /url/);
    const b = await header();
    assert.throws(() => verifyNip98(b.h, URL, 'GET', NOW), /method/);
    const c = await header({ kind: 1 });
    assert.throws(() => verifyNip98(c.h, URL, 'POST', NOW), /kind/);
    const d = await header();
    assert.throws(() => verifyNip98(d.h, URL, 'POST', NOW + 61), /expired/);
    const e = await header({}, [['u', URL], ['u', URL + '/x'], ['method', 'POST']]);
    assert.throws(() => verifyNip98(e.h, URL, 'POST', NOW), /url/);
});

test('refuses missing or malformed headers', () => {
    assert.throws(() => verifyNip98(undefined, URL, 'POST', NOW), /missing/);
    assert.throws(() => verifyNip98('Bearer x', URL, 'POST', NOW), /missing/);
    assert.throws(() => verifyNip98('Nostr !!!', URL, 'POST', NOW), /base64 JSON|not an event/);
});
