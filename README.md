# Login with Nostr

A drop-in "Login with Nostr" button for any website. One script, one div. The
user signs in with a Nostr key manager such as [NostrKey](https://nostrkey.com),
and your page receives their public key. No passwords, no email, no OAuth
provider. MIT licensed.

Live demo and docs: [loginwithnostr.com](https://loginwithnostr.com)

## Quick start

```html
<script src="/login.js"></script>
<div id="nostr-login"></div>

<script>
  document.addEventListener('nostr:login', (e) => {
    console.log('Clicked by', e.detail.pubkey);
  });
</script>
```

`login.js` is one file of about 8 KB with no dependencies. Copy it into your
site. A hosted copy is also available at `https://nostrkey.com/login.js`.

### Options

Set these on the div:

| Attribute | Values |
|---|---|
| `data-theme` | `dark` (default), `light` |
| `data-size` | `large`, `small` |
| `data-relay` | a `wss://` relay to ask the key manager to add on login |

Use `data-nostr-login` instead of `id="nostr-login"` for more than one button.

### Event

`nostr:login` fires once per login. It bubbles from the button's div to
`document`. `e.detail.pubkey` is the user's public key as 64 lowercase hex
characters.

## Before you ship

The script is small and does one job. These are the same habits you would use
for any code that touches login.

1. **Serve your own copy.** Download or fork `login.js`, read it, and host it on
   your own domain. Then nothing on your site changes unless you change it.
2. **Limit where scripts can come from.** Set a Content-Security-Policy that
   allows scripts from your own domain only. Add `https://nostrkey.com` only if
   you use the hosted copy.
3. **Check the signature on your server.** The `nostr:login` event tells your
   page who clicked. It is not proof, because any script on the page can fire
   it, and public keys are public. Before you create a session, verify a NIP-98
   signature on your server (below).
4. **Review updates before you take them.** Watch this repo and read a change
   before you pull it in.

## Verifying on your server (NIP-98)

In the browser, after `nostr:login`, ask the key manager to sign a NIP-98 event
for your login endpoint and send it in the `Authorization` header:

```js
document.addEventListener('nostr:login', async () => {
  const url = location.origin + '/api/auth/nostr';
  const auth = await window.nostr.signEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['u', url], ['method', 'POST']],
    content: '',
  });
  await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Nostr ' + btoa(JSON.stringify(auth)) },
  });
});
```

On the server, check the kind, the exact URL, the method, a short time window,
the event id and the signature, and refuse an event you have already seen.
Ready-made functions that do all of that:

- Node: [`examples/node/verify-nip98.mjs`](examples/node/verify-nip98.mjs), using
  [`nostr-crypto-utils`](https://www.npmjs.com/package/nostr-crypto-utils)
- Python: [`examples/python/verify_nip98.py`](examples/python/verify_nip98.py),
  using [`nostrkey`](https://pypi.org/project/nostrkey/)

Each returns the verified public key, or fails with a short reason. Start your
own session (cookie or token) for that key; how long it lasts is up to you.

The used-event list in the examples is kept in memory. If you run more than one
server, keep it in a shared store such as Redis.

## Tests

```bash
npm install
npm test
```

Runs the Node and Python verifier tests: a valid event passes once, and a
replay, changed content, another key, the wrong URL, method, kind or time, and
malformed headers are all refused.

## Security

See [SECURITY.md](SECURITY.md) to report a problem.

## License

MIT. Made by [Humanjava Enterprises](https://humanjava.com).
