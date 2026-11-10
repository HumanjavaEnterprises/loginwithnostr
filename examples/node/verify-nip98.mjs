// Verify a NIP-98 (kind 27235) Authorization header on your server.
// Uses nostr-crypto-utils (npm i nostr-crypto-utils). No framework needed.
//
//   const pubkey = verifyNip98(req.headers.authorization, 'https://example.com/api/auth/nostr', 'POST');
//   // pubkey is a verified 64-char hex key; start your session for it.
//
// Throws an Error with a short reason if anything is wrong.

// Use validateEventId and validateEventSignature. validateSignedEvent only checks the
// event's shape in nostr-crypto-utils 0.9.x, not its signature.
import { validateEventId, validateEventSignature } from 'nostr-crypto-utils';

const WINDOW_SECONDS = 60;
const seen = new Map(); // event id -> expiry (seconds). Use a shared store if you run several servers.

export function verifyNip98(authorization, expectedUrl, expectedMethod, now = Math.floor(Date.now() / 1000)) {
    if (typeof authorization !== 'string' || !authorization.startsWith('Nostr ')) {
        throw new Error('missing Nostr authorization');
    }
    let event;
    try {
        event = JSON.parse(Buffer.from(authorization.slice(6).trim(), 'base64').toString('utf8'));
    } catch {
        throw new Error('authorization is not base64 JSON');
    }
    if (!event || typeof event !== 'object') throw new Error('authorization is not an event');
    if (event.kind !== 27235) throw new Error('wrong kind');
    if (typeof event.pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(event.pubkey)) throw new Error('bad pubkey');

    if (!Number.isInteger(event.created_at) || Math.abs(now - event.created_at) > WINDOW_SECONDS) {
        throw new Error('expired or future-dated');
    }

    const tag = (name) => {
        const found = (Array.isArray(event.tags) ? event.tags : []).filter((t) => Array.isArray(t) && t[0] === name);
        return found.length === 1 ? found[0][1] : undefined;
    };
    if (tag('u') !== expectedUrl) throw new Error('url does not match');
    if (typeof tag('method') !== 'string' || tag('method').toUpperCase() !== expectedMethod.toUpperCase()) {
        throw new Error('method does not match');
    }

    // Checks the id is the hash of the event and the signature is valid for pubkey.
    if (typeof event.id !== 'string' || typeof event.sig !== 'string') throw new Error('bad signature');
    if (validateEventId(event)?.isValid !== true) throw new Error('bad signature');
    if (validateEventSignature(event)?.isValid !== true) throw new Error('bad signature');

    // Refuse the same signed event twice inside the window.
    for (const [id, exp] of seen) if (exp < now) seen.delete(id);
    if (seen.has(event.id)) throw new Error('already used');
    seen.set(event.id, now + WINDOW_SECONDS);

    return event.pubkey;
}
