# slicc-vault

The separate-origin vault at `vault.sliccy.ai`. It holds the sealed secrets, OAuth tokens, and model and MCP credentials of SLICC seven, so that no value ever reaches the model provider. The design is `secrets-tokens-design.md` (revision 4) in slicc-agent-plan. This README is the spec of what is built.

- **Built:** the key store, records, origin namespacing, auto-unlock with an optional passkey or passphrase lock, the embedding API with its `page` and `agent` roles, the page's `put`, `seal`, `remove`, `restore`, `cancel` and `lock`, the scrub state, the lock button and its popup, and the vault side of the `/dev/sealed` ops `seal`, `placeholder`, `list`, `test`, `request`, `status`, `cancel` and `materialize`.
- **Not built yet:** policy (every record is `inert`, and `test` always refuses), `forward` and the scrubber, exec, `import` and `export`, and the agent's ops. They answer as described below.

## Documents and hosting

The build (`npm run build`) writes a flat static tree to `dist/site/`:

| file | what it is |
|---|---|
| `index.html`, `frame.js` | the core frame. bios embeds it as a hidden iframe and talks to it over a `MessagePort` |
| `button.html`, `button.js` | the lock button. A popup can only open from a click inside a vault document, so bios and spectrum embed this wherever the lock is offered |
| `popup.html`, `popup.js` | the vault window, a top-level `vault.sliccy.ai` document, used only for the passkey or passphrase lock |
| `vault.css`, `fonts/` | Spectrum 2 from the CSS-only `@spectrum-css` packages, and Adobe Clean |
| `config.json` | `{ version, embedders }`. `embedders` is the fallback list, `["https://seven.sliccy.ai"]` |

There is no third-party JavaScript: the bundles hold only this repo's code. The sliccy-ai Worker serves the tree from the network on every load, never from OPFS, with:
- `Content-Security-Policy` with `script-src 'self'`, no inline scripts or styles, and `frame-ancestors` listing the seven origins;
- `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-site`, `Cross-Origin-Opener-Policy: same-origin`;
- `Origin-Agent-Cluster: ?1`, `nosniff`, `Referrer-Policy: no-referrer`, `no-cache` with an ETag.

`GET /embedders.json` is answered by the Worker, not by this tree. It returns `{ "embedders": [...] }`, the same sources as `frame-ancestors`. The vault reads it at start, falls back to `config.json` when it's missing or malformed, and accepts only those origins. An embedder source is `http(s)://host`, optionally with `:port` or `:*`, matched exactly.

`main` is served at `vault.sliccy.ai`, and every other branch at `vault-<label>.sliccy.ai`. seven embeds only `vault.sliccy.ai`.

## Storage and keys

Everything lives in the vault origin's IndexedDB, database `slicc-vault`, version 1:

| store | key | holds |
|---|---|---|
| `meta` | `"keys"` | the key state below |
| `records` | `[ns, kind, name]`, unique index on `placeholder` | records |
| `requests` | `id` | requests that wait for a human |
| `audit` | `seq` (auto-increment) | the audit log, per namespace |
| `intents` | `nonce` | hand-offs from a button to the popup, valid for 10 minutes |

**The data key** is one AES-GCM 256 key. Each record's value is encrypted under it with a fresh 12-byte IV and the additional data `slicc-vault/1 NUL ns NUL kind NUL name`, so a ciphertext can't be moved to another record.

**The key state** is one of:
- `auto` (the default): the data key is stored as a **non-extractable** `CryptoKey`. Every vault document loads it at start, so there's never a prompt.
- `passkey`: the data key is stored only wrapped (AES-GCM) under a key-encryption key from **WebAuthn PRF**. The passkey's RP id is the vault's host, the PRF input is a random 32-byte salt, and the KEK is HKDF-SHA-256 over the PRF output with that salt and the info `slicc-vault/kek/1`.
- `passphrase`: the same, with the KEK from PBKDF2-SHA-256, 600,000 iterations, over a random 16-byte salt.

**Locking:**
- While protected, a document starts locked and asks the other open vault documents (over the origin's `BroadcastChannel` `slicc-vault`) for the unwrapped key. Unlocking in the popup unwraps the key as non-extractable and hands it to every open vault document the same way.
- `Lock now` drops the key from every document. Closing every vault document has the same effect.
- **Protecting** makes a new data key, re-encrypts every record under it, and stores it wrapped, in one transaction. If a record changed meanwhile, protecting fails with `EAGAIN` and changes nothing. **Removing protection** stores the current key as non-extractable again.
- While locked, `seal` answers `EACCES` with a message starting `vault is locked`. Ops that need no value (`placeholder`, `list`, `status`, ...) still work.

## Records

```
{ ns, kind: "secret" | "grant" | "model" | "mcp", name, placeholder, sealed: { iv, data },
  source, createdAt, updatedAt, usedAt?, expiresAt?, refresh?, removedAt? }
```

- **`ns`** is the embedder's origin, below.
- **`name`** matches `^[A-Za-z_][A-Za-z0-9_]*$`, at most 128 characters.
- **A value** is at least 8 bytes of UTF-8, without CR, LF or NUL, and contains no placeholder. Anything shorter is refused with `EINVAL` "values shorter than 8 bytes can't be protected from the model", because the scrubber couldn't tell it apart from ordinary output.
- **`placeholder`** is `fnox_proxy_` plus 24 lower-case hex characters from `crypto.getRandomValues`, unique across the whole vault and stable for the record's life. All placeholders have the same length, so none contains another.
- **`source`** is `settings` (entered in spectrum), `process`, `jerk:<provider>@<device>`, `oauth:<provider>` or `import:<kind>`.
- **`state`** is computed, never stored: `removed` when `removedAt` is set, `active` when the accepted policy has a rule naming the record, otherwise `inert`. With no policy yet, every record is `inert`.
- **Removing** sets `removedAt`. A removed record keeps its placeholder, can be restored with `restore`, and is deleted for good 30 days later. Sealing a removed name brings it back with a new value and the same placeholder.
- **Times** are epoch milliseconds everywhere.

## Scrub state

`scrub { needed, version, ready }` tells bios and the agent whether output must pass the vault's scrubber before it reaches the model. It's per namespace:
- `needed` is false only when the namespace holds no plaintext at all: no record of any kind or state, removed ones included until they're purged.
- `version` counts every change to the namespace's set of values: each seal, rotation, removal, restore and purge.
- `ready` is false only when values exist but this vault frame never held the data key since it loaded, which is a reload with the lock on, before unlock. Locking again later doesn't clear it, because the compiled scrubber stays in memory for the frame's life.

It's in `status`, in `placeholders` replies and in every `placeholders` push. After `put` and `seal`, the push with the new pair goes out **before** the reply.

## Namespaces

Every record, request, audit entry and scrub version belongs to the origin that embeds the vault. The core frame takes it from the `event.origin` of the hello, and the button from `location.ancestorOrigins[0]` (or the first message's origin when the browser hides ancestors). A branch preview of bios therefore gets its own empty vault and never sees seven's records. The popup shows the namespace of the button that opened it. The lock itself is one per vault.

## The embedding API (core frame)

The embedder (bios) loads `https://vault.sliccy.ai/` in an iframe and, after `load`, posts a hello carrying a port:

```js
iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'hello', role: 'page' }, 'https://vault.sliccy.ai', [port2]);
```

- The frame answers only when the message comes from its own parent window, from an allowed origin, matching `location.ancestorOrigins[0]` when the browser exposes it. Anything else gets no answer at all.
- On `port2` it answers `{ v: 1, op: 'welcome', role, status }`, or `{ v: 1, op: 'refused', error }` for another protocol version or an unknown role.
- Everything after that goes over the port. The namespace and the role are fixed by the hello. Requests are `{ v: 1, id, op, ...fields }`; replies are `{ v: 1, id, op, ...fields }` or `{ v: 1, id, error: { code, message } }`. Each port is answered in order (FIFO).
- **Roles:** `page` (the default) is bios and spectrum. bios may hand spectrum a page port of its own, or relay; the messages are the same. `agent` is the port bios hands the agent worker: it may use only `redact`, `redactStream`, `push`, `end`, `drop`, `model`, `mcp`, `endpoints`, `records`, `grant` and `refresh` (all `ENOTSUP` in this version), and anything else is `EACCES`. The agent port gets no events.

| op (page role) | fields | reply |
|---|---|---|
| `sealed` | `req` (the `/dev/sealed` request object, or its JSON text), `stamp` (`{ pid, ppid, uid, gid, tag }` from the kernel) | `{ reply }`, the §3.7 reply, below |
| `status` | — | `{ status: { version, protocol, origin, locked, lock, scrub, waiting } }` |
| `placeholders` | — | `{ placeholders, scrub }`: every placeholder of a record that isn't removed, active and inert, sorted |
| `list` | — | `{ list: { secrets, refused, audit, auditMore, exits } }` for Settings › Secrets |
| `audit` | `before?` (a `seq`), `limit?` (1–1000, default 100) | `{ audit, more, next? }`, newest first; pass `next` as `before` for the next page |
| `put` | `name`, `value`, `request?` | `{ name, placeholder, state }`. A value typed in Settings, with source `settings`; on an existing name it's a rotation that keeps the placeholder. With `request`, it answers that pending value request (which must ask for `name`), so its `/dev/sealed` `status` becomes `done` |
| `seal` | `name`, `value`, `source`, `kind?` (default `secret`), `expiresAt?`, `refresh?` | `{ name, placeholder, state }`. bios's, for J1 leases and sign-in tokens |
| `remove`, `restore` | `name` | `{ name, placeholder, state }` |
| `cancel` | `request` | `{ state }`; the request's `/dev/sealed` `status` becomes `cancelled` |
| `lock` | — | `{}`; drops the key everywhere when the lock is on |
| `import`, `export`, anything else | | `ENOTSUP` |

`put` and `seal` need the vault unlocked. They answer `EACCES` with a message starting `vault is locked` otherwise.

**Events** on page ports:
- `{ v: 1, event: 'status', status }` whenever requests, records, the scrub state or the lock change;
- `{ v: 1, event: 'placeholders', placeholders, scrub }` whenever either changes;
- `{ v: 1, event: 'changed', parts }`, with `parts` among `secrets`, `audit` and `exits`, so a view knows what to reload.

**Errors** use errno names: `EINVAL`, `ENOENT`, `EACCES`, `EEXIST`, `EAGAIN`, `ETIMEDOUT`, `ENOTCONN`, and `ENOTSUP` for ops this version doesn't have.

## `/dev/sealed`, the vault side

bios relays each kernel request unchanged as the `sealed` op, with the kernel's stamp. The vault validates and answers `{ v: 1, ...fields }` or `{ v: 1, error: { code, message } }`. A request over 64 KiB, one that isn't a single JSON object, one with `v` other than 1, and an unknown `op` are `EINVAL`, as is a missing or malformed stamp.

| op | fields | reply |
|---|---|---|
| `seal` | `name`, `value` | `{ placeholder, state }`. A new name creates a `process` record. An existing one is rotated and keeps its placeholder, but only when its value came from a process; a value from Settings, jerk, OAuth or an import is replaced only by uid 0, and anyone else gets `EEXIST` |
| `placeholder` | `name` | `{ placeholder, state }`, including `removed`; `ENOENT` when there's no record |
| `list` | — | `{ secrets: [{ name, placeholder, state, exec, rules, expiresAt? }] }`, records of kind `secret` that aren't removed |
| `test` | `name`, `url`, `method?`, `header?` | `{ verdict, reason }`. Without policy it's always `refuse`; `ENOENT` for an unknown name |
| `request` | `kind: "value"`, `name`, `prompt?` (≤ 200 characters) | `{ state: "pending", id }` |
| `request` | `kind: "oauth"`, `provider`, `oauth` (an object) | the same |
| `request` | `kind: "jerk-seal"`, `provider` | the same |
| `status` | `id` | `{ state }`, with `placeholder` and `record` once a value request is `done` |
| `cancel` | `id` | `{ state }`: `cancelled`, or the state it had already reached |
| `materialize` | `names`, `path`, `argv`, `cwd` | checked, then always `EACCES` in this version |

- **Requests** expire 300 s after they're made. Each uid has at most one pending request per namespace; a second one is `EAGAIN`. `status` and `cancel` see only the caller's own requests (uid 0 sees all), and others get `ENOENT`.
- A value request shows up in `status.waiting` and is answered by the page's `put` with its `request` id, or ended by `cancel`. `oauth` and `jerk-seal` requests can only be cancelled in this version.

## The button (`button.html`)

A popup needs a click inside a vault document, so the way into the lock popup is this button. The embedder loads `https://vault.sliccy.ai/button.html` in an iframe and, after `load`, posts:

```js
frame.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'button', button: config }, 'https://vault.sliccy.ai');
```

**`config`** (`ButtonConfig` in the types):

| field | values | default |
|---|---|---|
| `intent` | `{ kind: 'unlock' }`, `{ kind: 'protect' }`, or `"auto"` | `"auto"` |
| `label` | text instead of the default label | per intent |
| `size` | `s`, `m`, `l` (24, 32 and 40 px high) | `m` |
| `variant` | `accent`, `primary`, `secondary` | `secondary` |
| `treatment` | `fill`, `outline` | `fill` |
| `quiet`, `disabled` | booleans | `false` |
| `scale` | `medium`, `large` | `medium` |
| `theme` | `light`, `dark` | the system's colour scheme |
| `dir`, `lang` | `ltr`/`rtl`, a language tag | `ltr`, `en` |

- **Sending `op: 'button'` again updates the same button in place.** The frame doesn't reload, and only the fields given apply on top of the defaults.
- `{ op: 'focus' }` moves keyboard focus into the button.
- `unlock` is labelled `Unlock vault`, and `protect` (set up or remove the lock) `Vault lock`. `"auto"` shows `Unlock vault` while the vault is locked, and otherwise no button at all (size 0×0).
- The background is transparent, and the button sits inside a 2 px inset so its focus ring isn't clipped. Pass `theme` to match the page: Chrome paints an iframe opaque when its colour scheme differs from the embedder's, so the frame takes the scheme of `theme`, and the browser default without it.

**Events** to the embedder, all `{ type: 'slicc-vault', v: 1, event, ... }`:
- `ready`, once;
- `size { width, height, inset }`, on every change, so the embedder sizes the iframe to it;
- `label { label }`, on every change, for the iframe's `title`;
- `focus { direction: 'next' | 'previous' }`, when Tab or Shift+Tab leaves the button;
- `popup { intent, state }`, with `state` `opened`, `done`, `cancelled`, `closed` (the window closed without an answer) or `blocked` (the browser blocked the window).

## The popup (`popup.html`)

The button writes its intent to `intents` under a random 128-bit nonce and opens `/popup.html#<nonce>` in a 460×680 window. The popup claims that intent and shows the namespace it was opened for. Without a valid nonce it shows only "Nothing to do here". It asks the browser to make the vault's storage persistent.

| intent | what the popup does |
|---|---|
| `unlock` | unlocks with the passkey or passphrase, then closes |
| `protect` | while unlocked: **Protect with a passkey** (WebAuthn PRF), **Protect with a passphrase** (at least 8 characters, typed twice), or, once protected, **Lock now** and **Remove protection** |

A locked vault asks to be unlocked first, whatever the intent.

## Types for bios and spectrum

The npm package `@ai-ecoverse/slicc-vault` holds only TypeScript types, built from `src/contract.ts`: the port API (`Hello`, `Greeting`, `Request`, `Reply`, `VaultEvent`, `Role`), the button (`ButtonConfig`, `ButtonMessage`, `ButtonEvent`), the popup (`PopupIntent`, `PopupState`), the page's results (`SealResult`, `ImportResult`), and the data Settings shows (`SecretView`, `VaultStatus`, `ScrubState`, `PendingRequest`, `AuditEntry`, `ExitPolicyView`, `VaultList`). `Availability` (`connecting`, `waiting`, `locked`, `ready`) is for bios to tell spectrum "waiting for the vault" and "unlock the vault to continue". They mean:

- **`EpochMs`**: milliseconds since the epoch. **`DeviceId`**: the same id bios uses for linked devices and trays, in `sourceDevice`, `device:<id>` exits and `ExitPolicyView.devices[].device`.
- **`Rule`**: `domain` is an exact lower-case host; `header` a lower-case header name; **empty `methods` or `paths` mean any**.
- **`exec`**: `false` means the value is never revealed to a program; `any`, `argv` (with `execArgv`, the allowed argv prefixes) and `shell` are the `[exec]` modes under which `fnox exec` may hand it to a program.
- **`exits`** is present only when `/etc/slicc/secrets-policy.toml` restricts that secret; absent means every exit (`page`, `proxy`, `tailscale`, `device:<id>`).
- **`kind`**: `secret` (a credential programs use through rules), **`grant`** (a sign-in's refresh token, never injected; show it as "Sign-in"), `model` (a model provider key), `mcp` (an MCP server credential). `provider` and `account` name the service and the signed-in account where one is known.
- **`AuditEntry`**: `forward` is a use of a value in a request, with the exit that carried it; **`materialize` is shown as "Revealed to a program"**; `seal`, `remove`, `restore` and `policy` (with its `changes`) record changes. Every entry has a `seq` for paging.
- **`VaultList.refused`** lists rules the vault dropped because they name a model or MCP endpoint.
- **`PendingRequest.prompt`** is untrusted, agent-written text of at most 200 characters.
- **`ExitPolicyView`** is read-only: the secrets `/etc/slicc/secrets-policy.toml` restricts to certain exits.

## Develop

```sh
npm install
npm run build      # dist/site and dist/types
npm run lint
npm test           # Chromium integration tests
npm start          # vault on http://vault.sliccy.localhost:8790, a test embedder on seven.sliccy.localhost
```

- **Integration tests** (`test/integration/`) run the built vault on a local server that sends the production headers, at `http://vault.sliccy.localhost:<port>`, with test embedders on `seven.`, `preview.` and `evil.sliccy.localhost`. Chromium treats `*.sliccy.localhost` as one site and as a secure context, so the embedded frame gets the same first-party storage it gets under `sliccy.ai`. They use slicc-shared-web's CDP harness, plus a second CDP session for popups and the virtual WebAuthn authenticator.
- **Unit tests** stay in the gitignored `test/unit/` (`npm run test:unit`), and the pre-commit hook requires them to cover every changed line of `src/`.
- The Biome, TypeScript, lefthook and Renovate configuration comes from [slicc-shared-web](https://github.com/ai-ecoverse/slicc-shared-web). There are no comments in any file.

## Release and deploy

- **Releases:** semantic-release on `main` tags a version from the conventional commits. It publishes the types package when the repository variable `NPM_PUBLISH` is `true`.
- **Deploy:** after semantic-release, the release job builds with the new version and publishes `dist/site/` to `vault.sliccy.ai` from the `production` environment. Every push to another branch publishes it to `vault-<label>.sliccy.ai`. Both use GitHub's OIDC token against sliccy-ai's `/api/publish` route (`edge/publish.mjs`), with no stored secret.
