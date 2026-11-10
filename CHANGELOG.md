# Changelog

## 1.1.0

- `nostr:login` now fires once per login. It used to reach `document`
  listeners twice.
- The public key from the key manager is checked to be 64 hex characters and
  lowercased before the event fires, and is shown on the button as text.
- Removed the documented `nostr:logout` event, which never fired.
- Added server examples for verifying NIP-98 signatures in Node and Python,
  with tests.

## 1.0.0

- The button as served from `https://nostrkey.com/login.js`.
