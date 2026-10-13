# slicc-vault

The separate-origin vault at `vault.sliccy.ai`. It holds the sealed secrets, OAuth tokens, and model and MCP credentials of SLICC seven, so that no value ever reaches the model provider. The design is `secrets-tokens-design.md` (revision 4) in slicc-agent-plan. This README is the spec of what is built.

- **Built:** the key store, records, origin namespacing, auto-unlock with an optional passkey or passphrase lock, the embedding API with its `page` and `agent` roles, the page's `put`, `seal`, `remove`, `restore`, `cancel` and `lock`, the scrub state, the lock button and its popup, the attested policy (rules, `[exec]`, `[exits]`, `[limits]`), the injector and `forward` with the response scrub (S1), the agent's `redact`, `redactStream`, `endpoints`, `model` and `mcp` (S3, S4), `records`, `grant` and `refresh`, the model and MCP refusal, exec tickets (`materialize` and `materializeConsume`), `import` (backups, KeePass, six's `secrets.env`) and `export`, sign-in tokens with their grants and refresh through `egress`, and the vault side of the `/dev/sealed` ops `seal`, `placeholder`, `list`, `test`, `request`, `status`, `cancel` and `materialize`.
- **The vault has no network stack.** It never fetches anything but its own `config.json` and `embedders.json`: bios sends every request the vault prepares.

## Documents and hosting

The build (`npm run build`) writes a flat static tree to `dist/site/`:

| file | what it is |
|---|---|
| `index.html`, `frame.js` | the core frame. bios embeds it as a hidden iframe and talks to it over a `MessagePort` |
| `button.html`, `button.js` | the lock button. A popup can only open from a click inside a vault document, so bios and spectrum embed this wherever the lock is offered |
| `popup.html`, `popup.js` | the vault window, a top-level `vault.sliccy.ai` document, used only for the passkey or passphrase lock |
| `vault.css`, `fonts/` | Spectrum 2 from the CSS-only `@spectrum-css` packages, and Adobe Clean |
| `config.json` | `{ version, embedders }`. `embedders` is `vault.sliccy.ai`'s fallback list, `["https://seven.sliccy.ai"]` |

The bundles hold this repo's code and `@ai-ecoverse/slicc-scrub`. The only third-party code is for KeePass imports: `kdbxweb` (with `@xmldom/xmldom` and `fflate`) and `hash-wasm`'s argon2, exact-pinned and bundled into a separate chunk under `chunks/` that the core frame loads only when a KeePass import starts; its wasm is inlined, never fetched. The sliccy-ai Worker serves the tree from the network on every load, never from OPFS, with:
- `Content-Security-Policy` with `script-src 'self'`, no inline scripts or styles, and `frame-ancestors` listing the seven origins;
- `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-site`, `Cross-Origin-Opener-Policy: same-origin`;
- `Origin-Agent-Cluster: ?1`, `nosniff`, `Referrer-Policy: no-referrer`, `no-cache` with an ETag.

`GET /embedders.json` is answered by the Worker, not by this tree. It returns `{ "embedders": [...] }`, the same sources as `frame-ancestors`. The vault reads it at start and accepts only those origins. When it's missing or malformed, only `vault.sliccy.ai` falls back to `config.json`; on every other host (`vault-preview.sliccy.ai`, branch previews, local) that means no embedders, so it fails closed. An embedder source is `http(s)://host`, optionally with `:port` or `:*`, matched exactly.

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
- Every data key has an id, stored with it. A seal checks that id in the same transaction that writes the record, so a value encrypted under a key that was replaced meanwhile is refused with `EAGAIN` rather than stored unreadable.
- While locked, `seal` answers `EACCES` with a message starting `vault is locked`. Ops that need no value (`placeholder`, `list`, `status`, ...) still work.

## Records

```
{ ns, kind: "secret" | "grant" | "model" | "mcp", name, placeholder, sealed: { iv, data },
  source, createdAt, updatedAt, usedAt?, expiresAt?, refresh?, oauth?, provider?, server?, settings?, removedAt? }
```

- **`ns`** is the embedder's origin, below.
- **`name`** matches `^[A-Za-z_][A-Za-z0-9_]*$`, at most 128 characters.
- **A value** is at least 8 bytes of UTF-8, without CR, LF or NUL, and contains no placeholder. Anything shorter is refused with `EINVAL` "values shorter than 8 bytes can't be protected from the model", because the scrubber couldn't tell it apart from ordinary output.
- **`placeholder`** is `fnox_proxy_` plus 24 lower-case hex characters from `crypto.getRandomValues`, unique across the whole vault and stable for the record's life. All placeholders have the same length, so none contains another.
- **`provider`** (a `model` record's pi-ai provider id, required, `^[a-z0-9][a-z0-9._-]{0,63}$`), **`server`** (an `mcp` record's MCP server name, optional) and **`settings`** (non-secret `NAME = text` pairs for a `model` or `mcp` record, at most 16, each at most 256 characters, e.g. `AWS_REGION`) bind a record to what may use it. In `list`, a grant shows the `server` or `provider` of the live tokens of the same `source` that name it as their `refresh`, when they all agree (and none when they don't, whatever the grant stored), for display and lookup only; nothing is copied onto the grant. A reseal without them keeps the stored ones, and one with them rebinds the record; a new `model` record without a provider is refused with `EINVAL` "a model record needs its provider".
- **`source`** is `settings` (entered in spectrum), `process`, `jerk:<provider>@<device>`, `oauth:<provider>` or `import:<kind>`.
- **`state`** is computed, never stored: `removed` when `removedAt` is set, `active` when the accepted policy has a rule for the record (below), otherwise `inert`.
- **Removing** sets `removedAt`. A removed record keeps its placeholder, can be restored with `restore`, and is deleted for good 30 days later. Sealing a removed name brings it back with a new value and the same placeholder. Removing a token removes the grant its `refresh` names (when the grant has the token's own `source`, and no other live token of that source still names it) in the same transaction, and restoring it restores that grant too, only when that grant was removed by this token's removal (the vault records which token took it) and is still within the 30 days; the one `remove` or `restore` audit entry names it as `grant`. Removing an already removed record, or restoring a live one, succeeds and changes nothing (its 30 days don't restart, and nothing is audited).
- **Times** are epoch milliseconds everywhere.

## Backup reminder

`status.exportedAt` is the time of the namespace's last successful `export`, or `null` if it never exported. `status.backupReminder` is `due` once the namespace holds a `secret` record and has never exported, `dismissed` after `dismissBackupReminder`, and `null` otherwise (no secrets yet, or exported).

## Policy

The rules come only from two root-owned kernel files. bios reads them with the kernel's page-only `kernel.attest(path)` (KS-7), at boot and whenever either file changes, and passes the results through unchanged:

```js
port.postMessage({ v: 1, id, op: 'policy', files: [await kernel.attest('/etc/fnox/config.toml'), await kernel.attest('/etc/slicc/secrets-policy.toml')] });
```

**An attestation** is exactly `{ path, bytes, uid, gid, mode, ino, mtimeMs, sha256, users, onRootFs, parents }`, nothing more or less:

| field | format |
|---|---|
| `path` | the canonical absolute path the kernel read (it refuses symlinks and mount points) |
| `bytes` | the file's bytes, a `Uint8Array`, read in the same step as the stats |
| `uid`, `gid`, `mode` | integers; `mode` includes the type bits (`0o100644`) |
| `ino`, `mtimeMs` | numbers |
| `sha256` | 64 lower-case hex characters |
| `users` | the kernel's users mode: `off`, `report` or `enforce` |
| `onRootFs` | true only on the root file system, under no mount |
| `parents` | every directory from `/` down to the file's, each exactly `{ path, uid, gid, mode }` |

The vault trusts a file only when:
- `path` is `/etc/fnox/config.toml` or `/etc/slicc/secrets-policy.toml`, and the object has exactly the fields above in those formats;
- the SHA-256 the vault computes over `bytes` equals `sha256` (the field alone is never trusted);
- `uid` is 0, and `mode` is a regular file with `mode & 0o022` of 0;
- `parents` lists exactly the directories above `path`, in order from `/`, each with uid 0, a directory type and `mode & 0o022` of 0;
- `onRootFs` is true, and `users` is `enforce`;
- `bytes` is UTF-8 and parses.

Otherwise the vault keeps the policy it last accepted for that file, so the rules it would have changed stay as they were (new ones stay inert), and warns, e.g. `rules not trusted: /etc/fnox/config.toml: kernel users must be enforce`. The reply is `{ accepted, files: [{ path, sha256, accepted, warnings }], rules: [{ secret, domain, header, methods, paths }], warnings }`, with `rules` the rules now in effect. `status.policy` repeats `files` from the last `policy` call, so Settings can show why rules aren't trusted.

**The KS-7 conformance fixtures** are `test/integration/fixtures/attest/*.json`: `{ description, trusted, reason?, attestation }`, with `bytes` as base64, written by `make.mjs` next to them. `good-*` must be trusted, and every `bad-*` must be refused with a warning containing `reason`. The vault's own tests run them through the `policy` op, and the kernel's tests can check that `kernel.attest` produces the good shape.

**`/etc/fnox/config.toml`**, the injection policy, read the way fnox reads it:
- `[secrets]`: entries whose `provider` (or the file's `default_provider`) is `seven`, and whose `value` is a placeholder.
- `[[proxy.rules]]`: `secret` (a seven entry of `[secrets]`), `domain` (one exact host, lower-cased), `header` (lower-cased, default `authorization`), `methods` (upper-cased; empty means any) and `paths` (each starting with `/`; empty means any). A rule that breaks any of this is dropped with a warning; the rest of the file still counts.
- A record of kind `secret` is `active` when the file's `[secrets]` entry of its name holds the record's own placeholder and at least one rule names it. A placeholder from another vault or an old record doesn't activate anything.
- Nothing else in the file counts: no imports, profiles or other providers.

**`/etc/slicc/secrets-policy.toml`**, read by the vault only:

```toml
[exec]
NPM_TOKEN = true
GITHUB_TOKEN = { argv = [["/usr/bin/gh", "release", "upload"]] }
OPENAI_API_KEY = { shell = true }

[exits]
NPM_TOKEN = ["page", "device:lars-air"]

[limits]
materialize_per_minute = 10
materialize_per_day = 200
shell_per_day = 5000
```

- `[exec]`: `false` is an explicit off, `true` is `exec: 'any'`, exactly `{ argv = [[…]] }` is `'argv'` (each prefix an absolute program path), and exactly `{ shell = true }` is `'shell'`. Anything else, a table with other or extra keys included, is a warning, and `exec` stays `false`. VAULT-1d acts on them.
- `[exits]` is **optional**: a secret without a line may use every exit; a line restricts it to the exits listed (`page`, `proxy`, `tailscale`, `device:<name>`). Unknown names are dropped from the line with a warning, which leaves the line narrower, never wider.
- `[limits]` overrides the defaults above with positive integers.

Accepted policy is kept per namespace in IndexedDB, and loaded when an embedder says hello. Each file is audited once per SHA-256 and verdict (the vault remembers the last 64 per file) as a `policy` entry, with `accepted`, any `warning`, and its `changes` against the previously accepted file: rules `added` or `removed`, `exec` modes, `exits` lines and `limits`. Any change to the accepted policy, or a new audit entry, pushes `changed` with `secrets`, `exits` and `audit`, and other vault documents of the namespace reload the policy. Each `policy` call reads, merges and writes the stored policy in one transaction, so two pages can't undo each other's update.

## Scrub state

`scrub { needed, version, ready }` tells bios and the agent whether output must pass the vault's scrubber before it reaches the model. It's per namespace:
- `needed` is false only when the namespace holds no plaintext at all: no record of any kind or state, removed ones included until they're purged.
- `version` counts every change to the namespace's set of values: each seal, rotation, removal, restore and purge.
- `ready` is false only when values exist, the vault is locked, and this frame has no compiled scrubber for the namespace: a reload with the lock on, before unlock. The scrubber (`@ai-ecoverse/slicc-scrub`, over every value of the namespace, records of every kind and state) is compiled whenever the frame holds the key and the set of values changed, and is kept in memory for the frame's life, so locking stops value use but never scrubbing.

It's in `status`, in `placeholders` replies and in every `placeholders` push. After `put` and `seal`, the push with the new pair goes out **before** the reply.

## Namespaces

Every record, request, audit entry and scrub version belongs to the origin that embeds the vault. The core frame takes it from the `event.origin` of the hello, and the button from `location.ancestorOrigins[0]` (or the first message's origin when the browser hides ancestors). A branch preview of bios therefore gets its own empty vault and never sees seven's records. The popup shows the namespace of the button that opened it. The lock itself is one per vault.

## The embedding API (core frame)

The embedder (bios) loads `https://vault.sliccy.ai/` in an iframe and, after `load`, posts a hello carrying a port:

```js
iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'hello', role: 'page', sudoGid }, 'https://vault.sliccy.ai', [port2]);
```

- The frame answers only when the message comes from its own parent window, from an allowed origin, matching `location.ancestorOrigins[0]` when the browser exposes it. Anything else gets no answer at all.
- On `port2` it answers `{ v: 1, op: 'welcome', role, status }`, or `{ v: 1, op: 'refused', error }` for another protocol version or an unknown role.
- Everything after that goes over the port. The namespace and the role are fixed by the hello. Requests are `{ v: 1, id, op, ...fields }`; replies are `{ v: 1, id, op, ...fields }` or `{ v: 1, id, error: { code, message } }`. Each port is answered in order (FIFO).
- **Roles:** `page` (the default) is bios and spectrum. bios may hand spectrum a page port of its own, or relay; the messages are the same. `agent` is the port bios hands the agent worker: it may use only `redact`, `redactStream`, `push`, `idle`, `end`, `drop`, `endpoints`, `model`, `mcp`, `records`, `grant` and `refresh`, and anything else is `EACCES`. The agent port gets no events. Its ops are below (The agent's ops).
- **Values:** only `forward` (inside the head it returns, where an accepted rule allows it), `materializeConsume` (for an `[exec]` grant) and `egress` (a refresh request) put a value into the page. On the agent port only `model` and `mcp` do: their reply's prepared request carries the provider's or server's credential in its headers or URL, only for that provider's or server's own URLs, for the agent worker's transport to send at once. It must never be logged, stored, retried from storage or shown. No other op, event or reply carries a value, and no value ever reaches the model.

| op (page role) | fields | reply |
|---|---|---|
| `sealed` | `req` (the `/dev/sealed` request object, or its JSON text), `stamp` (`{ pid, ppid, uid, gid, tag }` from the kernel) | `{ reply }`, the §3.7 reply, below |
| `status` | — | `{ status: { version, protocol, origin, locked, lock, scrub, waiting, exportedAt, backupReminder, policy } }` |
| `placeholders` | — | `{ placeholders, scrub }`: every placeholder of a record that isn't removed, active and inert, sorted |
| `list` | — | `{ list: { secrets, refused, audit, auditMore, exits } }` for Settings › Secrets |
| `audit` | `before?` (a `seq`), `limit?` (1–1000, default 100) | `{ audit, more, next? }`, newest first; pass `next` as `before` for the next page |
| `put` | `name`, `value`, `kind?` (`secret`, the default, `model` or `mcp`), `provider?`, `server?`, `settings?`, `request?` | `{ name, placeholder, state }`. A value typed in Settings (Settings › Accounts puts model keys as `kind: 'model'` with their `provider`), with source `settings`; on an existing name it's a rotation that keeps the placeholder. With `request`, it answers that value request, which must still be pending and ask for `name`, and the record must be a `secret` (else `EINVAL`, and nothing is stored), so its `/dev/sealed` `status` becomes `done` |
| `seal` | `name`, `value`, `source`, `kind?` (default `secret`), `expiresAt?`, `refresh?`, `oauth?`, `provider?`, `server?`, `settings?`, `request?`, `jerk?` | `{ name, placeholder, state }`. bios's, for J1 leases and sign-in tokens, below (Tokens and refresh) |
| `answer` | `request`, `state` (`progress` or `done`), `progress?` (≤ 200), `exit?`, `user?`, `scopes?`, `message?` (≤ 500), `rows?`, `placeholder?` | `{ state }`. The answer to a `jerk` or `unseal` request (or a sign-in that failed: for `oauth` and `jerk-seal`, `done` needs a nonzero `exit`, since only `seal` completes them); fields merge into the request, and `status` returns them. `rows` (for `jop: "list"`) are `{ provider, name?, env, device?, signedIn?, user?, scopes? }`, with any other field dropped, so no token can pass. For a `jop: "status"` answered `done` with `exit` 0, the vault adds the placeholder of the provider's own `oauth:<provider>` or `jerk:<provider>@…` record; a `placeholder` given by bios must be one of those records of the provider |
| `refresh` | `name` | `{ state: 'refreshed', expiresAt? }` or `{ state: 'requested' }`, below |
| `remove`, `restore` | `name`, `kind?` (default `secret`) | `{ name, placeholder, state }`. A record removed more than 30 days ago can't be restored (`ENOENT`) |
| `cancel` | `request` | `{ state }`; the request's `/dev/sealed` `status` becomes `cancelled` |
| `lock` | — | `{}`; drops the key everywhere when the lock is on |
| `dismissBackupReminder` | — | `{ backupReminder }`; the reminder becomes `dismissed` for this namespace |
| `policy` | `files` | the attested policy files, below (Policy) |
| `forward` | `head`, `body?`, `owner`, `exit`, `rawTraits`, with a `MessagePort` transferred alongside | the injected head, below (Forward) |
| `materializeConsume` | `ticket`, `stamp`, `path`, `resolved`, `argv`, `cwd`, `interpreters`, `trusted` | the values for the child's environment, below (Exec) |
| `import` | `kind`, `bytes`, `password?`, `pick?` | below (Import and export) |
| `export` | `passphrase` | `{ bundle, count }`, below |
| anything else | | `ENOTSUP` |

`put` and `seal` need the vault unlocked. They answer `EACCES` with a message starting `vault is locked` otherwise.

**Events** on page ports:
- `{ v: 1, event: 'status', status }` whenever requests, records, the scrub state or the lock change;
- `{ v: 1, event: 'placeholders', placeholders, scrub }` whenever either changes;
- `{ v: 1, event: 'changed', parts }`, with `parts` among `secrets`, `audit` and `exits`, so a view knows what to reload;
- `{ v: 1, event: 'refresh', name, source, expiresAt }`, when a J1 lease is due (below);
- `{ v: 1, event: 'egress', request }`, with a `MessagePort`, when the vault needs bios to send a request it built (below).

**Errors** use errno names: `EINVAL`, `ENOENT`, `EACCES`, `EEXIST`, `EAGAIN`, `ETIMEDOUT`, `ENOTCONN`, and `ENOTSUP` for ops this version doesn't have.

## `/dev/sealed`, the vault side

bios relays each kernel request unchanged as the `sealed` op, with the kernel's stamp. The vault validates and answers `{ v: 1, ...fields }` or `{ v: 1, error: { code, message } }`. A request over 64 KiB, one that isn't a single JSON object, one with `v` other than 1, and an unknown `op` are `EINVAL`, as is a missing or malformed stamp.

| op | fields | reply |
|---|---|---|
| `seal` | `name`, `value`, and for an MCP bridge `kind: "mcp"`, `server`, `url` | `{ placeholder, state }`. A new name creates a `process` record. An existing one is rotated and keeps its placeholder, but only when its value came from a process; a value from Settings, jerk, OAuth or an import is replaced only by uid 0, and anyone else gets `EEXIST`. **A bridge token** (§3.16.3, e.g. mcpcat's `--bearer`) is an `mcp` record bound to `server` and `url`, which must be a kernel-loopback URL (`http://<port>.kernel.localhost/…`, never 9222; anything else is `EACCES`). A page `put` or `seal` of the same name turns it into an ordinary `mcp` record, without the URL. It records the sealing uid, and resealing it, even after it was removed, is allowed only for a `process` `mcp` record sealed by the same uid, or by uid 0; anything else, a user-entered record included, is `EEXIST` |
| `placeholder` | `name` | `{ placeholder, state }`, including `removed`; `ENOENT` when there's no record |
| `list` | — | `{ secrets: [{ name, placeholder, state, exec, rules, expiresAt? }] }`, records of kind `secret` that aren't removed, with their rules and `[exec]` mode |
| `test` | `name`, `url`, `method?` (`GET`), `header?` (`authorization`), `exit?` (`page`) | `{ verdict: 'inject' \| 'refuse', reason }`: the injector's verdict for `Bearer <placeholder>` in that header, without sending anything; `ENOENT` for an unknown name |
| `request` | `kind: "value"`, `name`, `prompt?` (≤ 200 characters) | `{ state: "pending", id }` |
| `request` | `kind: "oauth"`, `provider`, `oauth` (an object) | the same |
| `request` | `kind: "jerk-seal"`, `provider` | the same |
| `request` | `kind: "jerk"`, `jop` (`list`, `status`, `create`), `provider?` (needed but for `list`), `scope?`, `params?` (an object) | the same, or `{ state: 'done', id, exit: 2, message }` for a J2 refusal |
| `request` | `kind: "unseal"`, `provider` | the same, or the J2 refusal |
| `status` | `id` | `{ state }`, with `placeholder` and `record` once the request is `done`, `jerk` for a sign-in or lease that reported it, and the latest `answer` fields (`progress`, `exit`, `user`, `scopes`, `message`, `rows`, `placeholder`) |
| `cancel` | `id` | `{ state }`: `cancelled`, or the state it had already reached |
| `materialize` | `names` (or `shellGrants: true`), `path`, `argv`, `cwd`, `interpreter?` | `{ ticket, expiresAt, real: { NAME: true \| false } }`, below (Exec) |

- **Requests** expire 300 s after they're made. Each uid has at most one pending request per namespace that waits for a human (`value`, `oauth`, `jerk-seal`, and `jerk` with `jop: "create"`); a second one is `EAGAIN`. `status` and `cancel` see only the caller's own requests (uid 0 sees all), and others get `ENOENT`. Only requests that wait for a human show in `status.waiting`.
- A value request is answered by the page's `put` with its `request` id. A sign-in or lease (`oauth`, `jerk-seal`) is answered by `seal` with `request` (Tokens and refresh). Every other kind is answered by the page's `answer`. `cancel` ends any of them and pushes `{ v: 1, event: 'cancelled', request, kind }` to the page, which passes it on to J1 where it can.
- **J-8's jerk requests** (§3.7.1): the vault only keeps their state; bios learns of them from the relay and answers. `jop: "create"` and `unseal` are for root and cones only (J2): the kernel stamp must have `users: 'enforce'`, and either uid 0 or the `sudo` group among its `groups`. bios names that group's gid as `sudoGid` in its hello; a page hello without it clears the namespace's gid. A stamp without `groups`, a vault without `sudoGid`, or any other mode refuses: the request is `done` with `exit: 2` at once, before bios sees anything. The tag is kept for audit and display only.

## Tokens and refresh

The vault has no network stack, so sign-ins run in seven's page (route (b), §3.11) and the vault keeps only the results.
- **A sign-in's tokens:** bios runs the sign-in, does the code exchange, and hands the results to `seal`, keeping no copy:
  - the refresh token as `{ kind: 'grant', name, value, source: 'oauth:<provider>', oauth: { tokenUrl, clientId, scope?, resource? } }`. A grant is never injected and never exported; `tokenUrl` must be `https:`, without userinfo (`user:pw@`, `user@`, even an empty `:@`, also when hidden by whitespace or backslashes the URL parser normalises: any `@` in the authority refuses);
  - the access token as `{ name, value, source: 'oauth:<provider>', expiresAt, refresh: '<grant name>' }`. A grant name needs an `oauth:` source and `jerk-seal` a `jerk:` one (`EINVAL`), and a refresh uses the grant only when its source is the token's own (else the grant is missing).
  - With `request` (only for a `secret`; the id of a pending `oauth` request for the same provider as `oauth:<provider>`, or a `jerk-seal` request for the provider of `jerk:<provider>@…`) and `jerk` (`{ exit, user?, scopes?, expires_at? }`), `seal` also answers that request, in the same transaction that stores the record (a request that ended meanwhile refuses with `EINVAL`, and nothing is stored): its `/dev/sealed` `status` becomes `done`, with `jerk`, the record's `placeholder` and `record` state.
- **A J1 lease:** `{ name, value, source: 'jerk:<provider>@<device>', expiresAt, refresh: 'jerk-seal' }`.
- **When a token is due** (5 minutes before `expiresAt`): the core frame checks once a minute, and right after a page says hello, for every connected namespace and for `secret`, `model` and `mcp` records alike, and `refresh { name }` asks for it at once. Vault frames of the same storage (several tabs) take a Web Lock per refresh source, so one grant is sent to its IdP by one frame at a time; a frame that finds the token changed while it waited (refreshed or sealed again) sends nothing and answers with the stored token's `{ state: 'refreshed', expiresAt? }`.
  - A `jerk-seal` token is announced once per `expiresAt` (kept in IndexedDB, so across frames), and again every 10 minutes while it stays unsealed, in case no live page heard it, with the `refresh` event, and bios runs J1 `seal` again (`{ state: 'requested' }`).
  - An OAuth token is refreshed in the vault: it builds `POST tokenUrl` with `grant_type=refresh_token`, the refresh token, `client_id` and any `scope` and `resource` (form-encoded), and sends it through bios with the `egress` event. bios sends the request through its exits and posts `{ status, headers, body }` (or `{ error }`) on the event's port within 30 s. The event goes to the page port of the namespace that connected last. A port that doesn't answer in time (`ETIMEDOUT`), closed or not, keeps its ops and events but gets no more `egress`, and the next refresh goes to the page port before it. The vault reads `access_token`, `expires_in` and any new `refresh_token`, checks them as values, and rotates the records in one transaction with the `refresh` audit entry (their placeholders stay; if the token or its grant was changed, removed or restored during the round trip, nothing is written and it answers `EAGAIN`). An `expires_in` of 0 makes the token due at once, and one that isn't a non-negative finite number is `EACCES: refresh failed: the IdP returned an invalid expires_in` (likewise a `refresh_token` that is present but not a string, a `token_type` other than `Bearer`, and `access_token`, `refresh_token`, `token_type` or `expires_in` given twice: `EACCES: refresh failed: the IdP returned NAME twice`); a response carrying `error` fails even with a token; a response without `expires_in` leaves the new token without an expiry, so it isn't refreshed again until a new one is sealed. It answers `{ state: 'refreshed', expiresAt? }`, without `expiresAt` when the token has none. A failed refresh is `EACCES: refresh failed: <the IdP's error code>`, scrubbed. Without a connected page it's `ENOTCONN`.
- `egress` carries the refresh token to the page, in transit only; the response goes back to the vault, never to the kernel.

## Import and export

Spectrum's Settings › Secrets reads the file and the password, and bios hands them over. Both need the vault unlocked. Like every page op, `export` trusts the page: under rev 4 seven's page is trusted with values in transit (§8), and a compromised seven origin is out of scope.

**`export { passphrase }`** returns `{ bundle: Uint8Array, count }`, a backup of the namespace's records of kind `secret`, `model` and `mcp` that aren't removed. Grants aren't included, because they need a fresh sign-in. The passphrase needs at least 12 characters. The bundle is UTF-8 JSON:

```json
{ "format": "slicc-vault-bundle", "v": 1,
  "kdf": { "name": "PBKDF2", "hash": "SHA-256", "iterations": 600000, "salt": "<base64url>" },
  "cipher": { "name": "AES-GCM", "iv": "<base64url>" },
  "data": "<base64url>" }
```

`data` is AES-GCM 256 (additional data `slicc-vault-bundle`) over `{ "records": [{ name, kind, value, placeholder, source, createdAt, expiresAt? }] }`. A successful export sets `status.exportedAt`.

**`import { kind, bytes, password?, pick? }`** runs in two steps:
- Without `pick` it answers `{ stage: 'pick', candidates: [{ name, kind, exists, suggestedRules?, refused? }] }`, for the human to choose from. `refused` says why a candidate can't be imported.
- With `pick` it seals the candidates picked, each given as `{ name, kind }` or, for kind `secret`, as just its name, and answers `{ stage: 'done', imported: [{ name, placeholder, state }], skipped }`. `skipped` lists picked names that were refused or not in the file, and `reasons` maps each to a short reason ("not a valid name", "values shorter than 8 bytes can't be protected from the model", "it isn't in the file", …), never a value or part of one. `outcomes` lists every picked candidate as `{ name, kind?, imported, reason? }`, which tells two candidates of the same name and different kinds apart (`kind` is absent only for a picked name that isn't in the file). Each record is stored in its own transaction, which also reserves a bundle's placeholder, so a record either lands whole or not at all; one that can't be stored (its placeholder was taken meanwhile, the vault was re-keyed) is listed in `skipped`, and the rest still import.

| `kind` | `password` | what becomes a candidate |
|---|---|---|
| `bundle` | the export passphrase | each record, with its kind, source (`import:bundle` when it isn't a valid source), expiry, `provider`, `server` and `settings` (a `model` record without a provider is refused with "a model record needs its provider"), and **placeholder**, so the policy files still match. A placeholder used by another record of the namespace, or by another embedder of this vault, is refused ("this app already has this secret under another name", "another app that uses this vault already has this secret; use it there, or add it here by hand"), as is a name whose record here has another placeholder ("this app already has a different secret with this name") |
| `keepass` | the master password (KDBX 3 or 4, as kdbxweb reads them; Argon2 through hash-wasm) | each entry with a password, named after its title (upper-cased, other characters as `_`, a leading digit prefixed with `_`; a name already taken by an earlier entry gets `_2`, `_3`, …), source `import:keepass` |
| `six` | — | each `NAME=value` line of six's `secrets.env` (`export` and quotes allowed), source `import:six`. `NAME_DOMAINS` becomes `suggestedRules`: a `[[proxy.rules]]` stanza per exact domain, for the human to add with `sudo`, and a note for each wildcard, which isn't carried over |

Values are checked as at `put` (at least 8 bytes, no CR, LF or NUL, no placeholder). An existing name is rotated, keeping its placeholder. A wrong password or passphrase is `EACCES`.

## Exec

`fnox exec` (§3.5) asks for a one-shot ticket, and the kernel redeems it when it execs the child.

**`materialize`** (a `/dev/sealed` op) takes `names`, `path` (the absolute program fnox will exec), `argv` (exact, `argv[0]` included), `cwd`, and optionally `interpreter`: fnox's claim of the absolute shebang or binfmt interpreter of `path`, omitted for a native program. It's only a claim; the kernel's chain at consume decides. `shellGrants: true` (`fnox exec --shell-grants`) adds every `shell = true` secret to `names`, which may then be omitted.
- Each name must be a `secret` record (`ENOENT` otherwise) that hasn't expired (`EACCES: NAME expired; refreshing`). `real` says which will get their value: removed records and secrets without an `[exec]` grant stay `false` and keep their placeholder.
- **`true`** (exec `any`): refused with `EACCES` when `path`, or `interpreter`, is a shell (`sh`, `bash`, `dash`, `zsh`, `fish`, `busybox`, `jsh`), an interpreter (`python*`, `node`, `deno`, `bun`, `perl`, `ruby`, `php`, `lua`, `wasmer`, `awk` and `gawk`/`mawk`/`nawk`, `sed`, `tclsh`, `expect`, `R`, `Rscript`, `irb`) or an env dumper or wrapper (`env`, `printenv`, `xargs`, `sudo`, `su`, `nohup`, `timeout`, `time`, `nice`, `strace`), by basename.
- **`{ argv = [[…]] }`**: `real` only when `[path, ...argv[1..]]` starts with one of the listed prefixes. A listed shell or interpreter is allowed.
- **`{ shell = true }`**: always `real`, with no program refusal.
- **Limits,** per secret and uid, counted from the audit log: `materialize_per_minute` (10) and `materialize_per_day` (200), and `shell_per_day` (5,000, with no per-minute limit) for shell grants. Over a limit is `EAGAIN: materialize limit for NAME (10/min)`.
- A locked vault answers `EACCES` (`vault is locked`).
- Each real name is audited as `materialize { name, exec, path, argv, argvSha256, cwd, pid, ppid, uid, tag, ticket, consumed: false }`. `argv` is joined with spaces, scrubbed, and cut to 200 characters; `argvSha256` is the SHA-256 of each argument followed by a NUL byte.
- The reply never carries a value. The ticket is 32 hex characters and expires after 30 s.

**`materializeConsume`** (a page op, from bios for the kernel at exec) takes `{ ticket, stamp, path, resolved, argv, cwd, interpreters, trusted }`, all from the kernel and relayed unchanged:
- `stamp` is the exec'ing process.
- `resolved` is the kernel-normalised file that actually runs: `path` with every symlink resolved.
- `interpreters` is the absolute, symlink-resolved shebang/binfmt chain the kernel resolved for `path`, empty for a native binary. A plain `#!/usr/bin/env X` (or `env -S`) is reported as the resolved `X`; `env` with any other option or a `NAME=value` assignment is reported as `env` itself.
- `trusted` is true when the program and every chain entry are root-owned regular files, not group- or other-writable, under root-owned, non-writable parents (the attestation rule). Under users `off` it's always false.

The vault burns the ticket, then requires that:
- it's unexpired and from this namespace, `stamp.ppid` is the pid that asked, and `path`, `argv` (element by element) and `cwd` are exactly the ones it was issued for;
- `resolved` is an absolute path (missing or malformed refuses), `interpreters` a list of absolute paths and `trusted` a boolean; a claimed `interpreter` from fnox equals `interpreters[0]` (without a claim, the kernel's chain is taken as it is);
- each real name is still granted by the policy as stored now (reloaded at materialize and at consume): a removed grant, or an `{ argv }` grant that no longer lists the command, refuses;
- under that name's mode, the chain passes:
  - `true`: no entry of `path`, `resolved` and `interpreters` is on the refusal list, so neither a `#!/usr/bin/env node` script nor a symlink `/tmp/l → /bin/bash` passes, and `trusted` is true ("the program or its interpreter can be changed by a non-root user" otherwise), so a renamed copy of a shell, which its non-root maker owns, doesn't pass either;
  - `{ argv }`: the listed program is `path`, and when `path` is a link to a refused program the rule must also list that `resolved` program by its real path ("list it in [exec] by its real path"), so a listed `/tmp/l` that is repointed to `/bin/bash` refuses. Whatever chain the kernel resolved for it is allowed, so a rule for `npm publish` allows `/usr/bin/npm`'s `node`. But when `resolved` or the chain is a refused program and `trusted` is false, it refuses ("the program or its interpreter can be changed by a non-root user"), and `env` and the other wrappers in the chain always refuse;
  - `{ shell = true }`: any program and chain, the explicit exception;
- no real record has expired meanwhile.

Any failure is `EACCES: ticket refused: …`, and the ticket stays burned. It answers `{ values: { NAME: value }, placeholders: { NAME: placeholder } }` for the names that were real and still exist, and marks their audit entries `consumed`. The kernel swaps each env var whose value is exactly one of those placeholders, and compiles its own scrubber over these values for the child's output (S2).

## Forward

bios's exit router asks the vault to inject a request the kernel forwarded (an owner-bearing request that carries a placeholder), then sends it itself:

```js
const channel = new MessageChannel();
port.postMessage({ v: 1, id, op: 'forward', head, body, owner, exit, rawTraits }, [channel.port2]);
```

- `head` is `{ method, url, headers: [name, value][] }`; `owner` the kernel's `{ pid, ppid, uid, gid, tag }`; `exit` the exit bios chose (`page`, `proxy`, `tailscale` or `device:<name>`); `rawTraits` that exit's `{ manualRedirects?, encodedBodies? }`. `body` (bytes or a string) is needed only for MCP requests (below); for every other request it stays in bios, because bodies are never injected.
- **The reply** is `{ head }`, the same head with the values filled in, or `{ refused: { status, reason } }`: `403` with a one-line reason, or `502` for an exit with encoded bodies. A refused request must not be sent anywhere. Malformed fields are `EINVAL`.
- **The response** goes back over `channel.port1`, scrubbed: bios posts `{ op: 'response', status, statusText, url, redirected?, headers }`, then any number of `{ op: 'body', chunk: Uint8Array }`, then `{ op: 'end' }` or `{ op: 'error', message }`. The vault answers with the same messages, with `statusText`, `url`, every header name and value, the body and the error scrubbed over every value of the namespace. A value in its raw form comes back as its placeholder, anything else as `[redacted:NAME]`. The body is scrubbed as a stream; after 250 ms without input, a held tail shorter than 16 bytes is let through.

**The injector**, fnox's proxy semantics:
- **Hosts** are compared lower-cased, without a trailing dot, in rules, the refusal list and MCP servers alike.
- **Refused before anything is sent:** a placeholder in the URL or in a header name; credentials in the URL; a scheme other than `https:` or a port other than 443 (except §3.16.3's kernel servers, below); an ambiguous path (`.`/`..` segments, `\`, `%2e`, `%2f`, `%5c`, `%25`, checked on the raw URL); an exit with encoded bodies; no placeholder of this vault at all; a record that is removed, expired ("NAME expired; refreshing") or not a `secret`; a locked vault; no rule (in `/etc/fnox/config.toml`) whose exact domain, header, method and path allow it; an exit the secret's `[exits]` line doesn't list; the same placeholder twice in one header value; a header other than `authorization` on an exit that follows redirects (`manualRedirects` false); CR, LF or NUL after substitution.
- **Paths** in rules are globs: `*` stays within a segment, `**` crosses segments, `?` is one character.
- **Injected:** each placeholder is replaced inside the rule's header value, so `Bearer …` and `token …` templates work. In `Authorization: Basic`, the credential is decoded, the user and password parts substituted (a substituted user may not contain `:`), and re-encoded. A Basic value that holds a placeholder but isn't valid base64 of UTF-8 is refused.
- **Audited:** each injection adds a `forward` audit entry `{ name, domain, method, path, rule, exit, uid, tag }` and sets the record's `usedAt`. Never headers, bodies or values.

## Model and MCP endpoints

The vault never injects a secret into a model or MCP endpoint, whatever a rule says.
- **The built-in list** is generated at build time (`scripts/endpoints.mjs`, into the gitignored `src/endpoints.json`) from every provider base URL in pi-ai's catalog (`@earendil-works/pi-ai`, pinned in `devDependencies`), plus `bedrock-runtime.*` and `bedrock-runtime-fips.*.amazonaws.com`, Azure OpenAI and AI services, and Adobe's LLM proxy. Each entry is a host (with `*` for one label) and a path prefix (`*` for one segment, from templated segments).
- **Registered endpoints:** the agent's `endpoints` op adds model base URLs and MCP servers for its namespace. They only ever add.
- **At policy parse:** a rule that can reach only refused URLs (its domain matches, and the endpoint has no path prefix or every path of the rule lies under it) is dropped and listed in `list.refused` with the reason `NAME: host is a model or MCP endpoint; the vault never injects there`. Other rules on the same host stay.
- **At request time:** `forward` refuses any URL under the refused set, before rules: `403 host is a model or MCP endpoint; the vault never injects there`.
- **Kernel programs calling a registered MCP server (§3.16.1):** a `forward` whose URL lies under a registered MCP server isn't refused but handled for that server only. Only `mcp` records the server lists in `names` are filled in; a `secret`, `grant` or `model` placeholder is refused ("secrets are never sent to model or MCP endpoints"). The reply carries `body`, the request body scrubbed over every value, which bios sends instead of its own copy; the response is scrubbed as above; each call is audited as `mcp` with `server`, uid and tag.
- **`http://<port>.kernel.localhost/<path>`** (port 1–65535, never 9222, no explicit port) is the one `http:` form an MCP server may have (§3.16.3). Everything else must be `https:` on 443.

## The agent's ops

| op | fields | reply |
|---|---|---|
| `redact` | `texts`: strings and `Uint8Array`s | `{ texts, hits, version }`: each text scrubbed, in the same order and type; `hits` totals `{ name, form, count }` |
| `redactStream` | `stream` (an id) | `{ stream, idleMs, version }`; at most 64 streams per port (`EAGAIN`) |
| `push` | `stream`, `chunk` (bytes) | `{ chunk }`: what can be released, scrubbed |
| `idle` | `stream` | `{ chunk }`: a held tail under 16 bytes, after `idleMs` without input |
| `end` | `stream` | `{ chunk, hits }`: the rest, and the stream is gone |
| `drop` | `stream` | `{}` |
| `endpoints` | `model?`: https base URLs, or `{ provider, url }` for a provider's custom base URL; `mcp?`: `{ server, url, names?, tokenUrl? }` or a URL string | `{ ok: true }`; registrations only add: a server's first `tokenUrl` stays, for every URL it registers. New entries re-check the policy and push `changed` |
| `model` | `provider?`, `request`: `{ method, url, headers: [name, value][], body?: string \| bytes }` | `{ request, hits, version }`, the request prepared for the agent's transport, below |
| `mcp` | `server`, `request` (the same shape) | `{ request, hits, version }`, below |
| `records` | — | `{ records: [{ kind, name, placeholder, state, provider?, server?, expiresAt?, settings? }] }`: the namespace's `model` and `mcp` records that aren't removed, `state` being `ready`, `expired` or `refreshing` (expired with a refresh source), and `settings` scrubbed over every value (an entry whose name holds a value is dropped; so is a record whose name, provider or server holds one, and an `expiresAt` whose digits are a value). Never a value, a `secret` or a `grant`; the records are read and scrubbed under one scrub version (retried, then `EAGAIN` while values keep changing); `EACCES` while the vault is locked before its first unlock |
| `grant` | `server`, `response` (the token endpoint's body, a string or bytes), `oauth` (`{ tokenUrl, clientId, scope?, resource? }`), `name?` (a record name; anything else is `EINVAL`) | `{ response, records: [{ kind, name, placeholder }], expiresAt? }`, below |
| `refresh` | `server` or `provider`, `name?` | `{ state: 'refreshed', expiresAt? }`: refreshes that server's or provider's token in the vault, as Tokens and refresh describes (an `expiresAt` is left out when its digits are a value before or after the refresh, the replaced and the new token included, or when any other value changed while it ran); `ENOENT` when it has none, `EINVAL` when it has several and no `name` picks one |

**Preparing model and MCP requests (§3.12).** Every model and MCP request of the agent worker goes through `model` or `mcp`, with or without a credential; the response comes back to the worker directly.
- **The head carries no value:** checked with the scrubber from before and after any refresh or rotation during the request, a raw value (in any form the scrubber knows) in the method, the URL, a header name or a header value is `EACCES` ("the request head carries a value; send its placeholder instead").
- **The body** (a string or bytes, at most 32 MiB of UTF-8) is scrubbed over every value of the namespace (S4), with both of those scrubbers, so neither a token refreshed for this request nor a value rotated meanwhile slips through and keeps its type; placeholders in it are left alone. The URL must be `https:`, or for `mcp` the kernel loopback `http://<port>.kernel.localhost/…` (port 9222 refused) under that server's own loopback registration; anything else is `EACCES` ("model and MCP requests go out over https only").
- **The credential goes in by placeholder.** The worker sets a provider's API key (or `mcp.json`'s `${NAME}`) to the record's placeholder from `records`, and the vault replaces it with the value **only in the headers and the URL** (URL-encoded there), never in the body. Every placeholder of the namespace in the headers or URL must belong to the target, else `EACCES` ("NAME isn't a credential of TARGET; secrets are never sent to model or MCP endpoints"): for `model`, a `model` record of that `provider`; for `mcp`, an `mcp` record bound to that `server` or listed in its `names`; a bridge token sealed by a program only when the server's registration has exactly its `url` and the request is under that `url` itself (never at the server's `tokenUrl`). A `secret` or `grant` is never filled in, nor a credential whose value contains or equals another record's value in any form the scrubber knows except a 16-character fragment (`EACCES`). Every string in the replies of `model`/`mcp` (outside the prepared head), `records`, `grant` and `refresh`, and every error message, is scrubbed over every value, and a number whose digits are a value is left out.
- **Its own URLs only.** `model` fills a key only under that provider's built-in base URL (pi-ai's catalog, generated with the provider ids) or a `{ provider, url }` registered with `endpoints`; `mcp` only under that server's registered URL (same scheme and port), at exactly its `tokenUrl`, or at its kernel loopback URL. Elsewhere a filled placeholder is `EACCES` ("NAME is sent only to TARGET's own endpoints"). A request without such a placeholder is only scrubbed, wherever it goes over `https:`, so OAuth discovery and client registration work.
- **`provider` is optional:** without it, the provider is the one of the single `model` placeholder in the headers and URL; with none or several, nothing is filled.
- **An expired record** with a refresh source is refreshed first, once per prepared request however often its placeholder appears, through `egress` (`EACCES` "NAME expired; refreshing" if that fails); one without is `EACCES` "NAME expired". A removed record is `EACCES`. A locked vault before its first unlock is `EACCES` ("unlock the vault to continue").
- **Consistency:** if the namespace's values change while a request is prepared by more than the one change each of its own refreshes makes, it's `EAGAIN` ("prepare the request again"), and a credential that a refresh rebinds to another provider or server is `EACCES`; `grant`'s kept fields also have the returned tokens replaced by their placeholders directly, and its record names and `expiresAt` are scrubbed against a value stored meanwhile.
- **The reply carries the value,** in `request.headers` or `request.url`, for the worker's transport to send at once. It is never logged, stored, retried from storage or shown; after a 401 the worker calls `refresh` once and prepares the request again.

**MCP OAuth (`grant`).** The worker registers the server with its `tokenUrl`, sends the code exchange through `mcp` (to exactly `tokenUrl`, with no credential), and hands the token endpoint's body to `grant`, holding it only in transit.
- `oauth.tokenUrl` must be `https:` and the server's registered `tokenUrl` (`EACCES` otherwise). A server or record name that holds a stored value or one of the returned tokens, in any encoded form, is `EINVAL`. The body is checked as for a refresh (an object with a string `access_token`, no `error`, `token_type` Bearer if present, a valid `expires_in`), and every token must be a valid value (`EINVAL` otherwise), before anything is stored.
- The access token is sealed as an `mcp` record bound to `server`, named `name` or `<SERVER>_ACCESS_TOKEN` (upper-cased, other characters as `_`, `MCP_` in front of a leading digit), with source `oauth:mcp` and `expiresAt` from `expires_in`. A `refresh_token` is sealed as a `grant` named `<name>_GRANT` with `oauth` and the same `server`, and becomes the token's refresh source.
- Both records are written in one transaction, so `grant` stores all or nothing. The reply's `response` is JSON, a string or bytes like the input, with only `access_token` and `refresh_token` (as their placeholders), any string `token_type`, a numeric `expires_in` that isn't a stored value, and string `scope` scrubbed over every value; every other field, `id_token` included, is dropped. A `grant` whose access-token name is already bound to another server is `EEXIST`, checked in the same transaction.

A stream is compiled against the namespace's values when it opens. If a value is added, rotated or removed while it's open, its next `push`, `idle` or `end` answers `EAGAIN` and the stream is gone: open it again and push the output from its start.

`redact` and `redactStream` need a compiled scrubber: with the lock on, before the first unlock since the frame loaded, they answer `EACCES` ("unlock the vault to continue"). They never return a value: matches are replaced, everything else passes through.

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
| `protect` | while unlocked: **Protect with a passkey** (WebAuthn PRF), **Protect with a passphrase**, or, once protected, **Lock now** and **Remove protection** |

- A locked vault asks to be unlocked first, whatever the intent.
- A wrong passphrase or passkey says so ("That passphrase doesn't unlock this vault."), and a wrong passphrase is cleared from the field.
- A new passphrase needs at least 12 characters, typed twice. The popup says what's missing as you type, and **Protect** stays disabled until both fields pass.
- **Remove protection** asks first: "Remove protection? The vault will unlock by itself on this device." 

## Types for bios and spectrum

The npm package `@ai-ecoverse/slicc-vault` holds only TypeScript types, built from `src/contract.ts`: the port API (`Hello`, `Greeting`, `Request`, `Reply`, `VaultEvent`, `Role`), the button (`ButtonConfig`, `ButtonMessage`, `ButtonEvent`), the popup (`PopupIntent`, `PopupState`), the page's results (`SealResult`, `ImportResult`), and the data Settings shows (`SecretView`, `VaultStatus`, `ScrubState`, `PendingRequest`, `AuditEntry`, `ExitPolicyView`, `VaultList`). `Availability` (`connecting`, `waiting`, `locked`, `ready`) is for bios to tell spectrum "waiting for the vault" and "unlock the vault to continue". They mean:

- **`EpochMs`**: milliseconds since the epoch. **`DeviceId`**: the same id bios uses for linked devices and trays, in `sourceDevice`, `device:<id>` exits and `ExitPolicyView.devices[].device`.
- **`Rule`**: `domain` is an exact lower-case host; `header` a lower-case header name; **empty `methods` or `paths` mean any**.
- **`exec`**: `false` means the value is never revealed to a program; `any`, `argv` (with `execArgv`, the allowed argv prefixes) and `shell` are the `[exec]` modes under which `fnox exec` may hand it to a program.
- **`exits`** is present only when `/etc/slicc/secrets-policy.toml` restricts that secret; absent means every exit (`page`, `proxy`, `tailscale`, `device:<id>`).
- **Bindings in `list`:** read under one scrub version (retried, then `EAGAIN`), `provider`, `server` and `settings` are scrubbed over every value (a setting whose name holds one is dropped), and left out while the vault is locked before its first unlock.
- **`kind`**: `secret` (a credential programs use through rules), **`grant`** (a sign-in's refresh token, never injected; show it as "Sign-in"), `model` (a model provider key), `mcp` (an MCP server credential). `provider` and `account` name the service and the signed-in account where one is known; a `model` record always has its `provider`, an `mcp` record may have its `server`, and either may carry non-secret `settings`.
- **Who did it:** `uid` and `tag` are the kernel stamp for entries a program or the agent caused (`/dev/sealed` seals, `forward`, `mcp`, `materialize`). Every entry from a page-role op (`put`, `seal`, `remove`, `restore`, `import`, `policy`) and from the vault itself (`refresh`) has `uid: null, tag: null`, older entries included. Spectrum shows page ops as "by you", `refresh` as "automatically", and `policy` entries with no "by …".
- **`AuditEntry`**: `forward` is a use of a value in a request, with the exit that carried it; `mcp` a kernel program's call to a registered MCP server; **`materialize` is shown as "Revealed to a program"**; `seal`, `remove`, `restore` and `policy` (with its `changes`) record changes. Every entry has a `seq` for paging.
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
