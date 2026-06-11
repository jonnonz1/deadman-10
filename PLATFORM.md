# deadman-10 — Multi-Tenant Platform Design (§7)

The original ask (turn one) was **"many independent owners"** — a service where each
person runs their own private dead-man switch on shared infrastructure. Everything
built so far is the **single-owner** tool. This document specifies the multi-tenant
platform *before* any code, because it has a **different threat model**: the platform
operator becomes a partially-trusted party with power over every tenant.

> **Thesis.** The single-owner design already does the hard part. Its three load-bearing
> properties — *the host holds only ciphertext*, *the timelock fires with no operator*,
> and *check-ins are authenticated* — were built for a host you don't fully trust. A
> multi-tenant operator is just that same untrusted host, generalised to N owners. So the
> platform is mostly a **scaling + operational** layer over guarantees that already hold,
> **provided it stays zero-knowledge.** The one genuinely new problem is **liveness
> integrity**: the operator runs everyone's timer, so it can suppress or mis-fire.

---

## 1. What changes when you go multi-tenant

| | Single-owner (built) | Multi-tenant (this doc) |
|---|---|---|
| Who runs `watch` | you, on your host(s) | the operator, for all tenants |
| Confidentiality root | host holds only ciphertext + public keys | **same** — operator holds only ciphertext + public keys |
| Liveness timer | your cron/launchd | operator's scheduler, per tenant |
| New adversary | host-local malware | **the operator itself** (sees all tenants, runs all timers) |
| Blast radius of a bug | one switch | **every tenant** (H1–H8 multiply by N) |

The trust boundary is redrawn: the operator is **untrusted for confidentiality and for
honest timing**, trusted only for **availability of the convenience layer** (and even
that is backstopped by drand).

---

## 2. The operator-as-adversary threat model

Enumerate what a malicious or compromised operator can attempt, and where each lands:

| Operator attack | Can they? | Why / mitigation |
|---|---|---|
| **Read a tenant's secrets** | ❌ | Platform stores only ciphertext encrypted to the beneficiary's key (zero-knowledge, §3). A breach of the whole platform leaks only ciphertext. |
| **Forge a tenant's check-in** (suppress fire by faking liveness) | ❌ | Check-ins are owner-signed tokens (H5); the operator holds only the check-in *public* key and cannot mint a valid token. |
| **Suppress firing** (refuse to run a tenant's timer) | ⚠️ partial | The operator *can* simply not fire. Mitigated by the **drand timelock backstop** (§4): the switch fires without the operator. Suppression of the convenience layer ≠ suppression of the fire. |
| **Force an early fire** on a live, checking-in owner | ⚠️ **real, bounded by ≤1 re-arm window — this IS a delayed disclosure, not a non-event** | The operator holds the liveness state, so it doesn't need to *forge* anything (signed tokens stop forgery). It can **(a)** refuse to honour a re-arm — keep the old share with the nearer `T` so it fires at the old deadline; or **(b)** advance the stored monotonic floor so the owner's validly-signed "now" check-in is rejected as stale → never recorded → ages → fires. Either way an **irreversible** fire happens within **≤ one re-arm window**, and the published share opens automatically at its `T` — you cannot un-publish it. It is bounded (the window) and the operator still can't *read* the vault, but it is a real operator-triggered disclosure. **Defense = detectability:** the client must verify the *actual published timelock round* independently of the operator's status API (§8) and migrate if re-arms aren't landing. |
| **Cross-tenant leak** (tenant A reads/triggers tenant B) | ❌ by design | Per-tenant isolation (§5): authenticated state keyed per owner, no shared mutable state, one isolate per tenant. |
| **Tamper a tenant's liveness state** (roll back to force fire) | ⚠️ partial | Authenticated check-in tokens cover the timestamp + monotonic floor (H4+H5); the operator can drop state (→ suppression, handled above) but can't forge a *newer* signed check-in, and can't manufacture a *valid* older one past the floor. |
| **Roll the whole platform back / replay** | ⚠️ | Monotonic floor per tenant + signed tokens bound replay. A operator who silently freezes everything is doing suppression (backstopped by drand). |
| **Subpoena / coercion of the operator** | ✅ but useless | The operator can hand over everything it has — which is ciphertext + timers + public keys. Nothing readable. |

**The shape of the result:** confidentiality and check-in-forgery are *fully* closed by
the zero-knowledge + signed-token design. The operator's only real power is **denial**
(don't fire) and **premature publication of unopenable ciphertext** — both bounded by the
drand timelock, which is the platform's load-bearing backstop exactly as it is for the
single-owner switch.

---

## 3. Zero-knowledge is non-negotiable

The whole platform rests on: **the operator never holds anything that decrypts a vault.**
Concretely, per tenant the platform stores ONLY:

- the **vault ciphertext** (or a pointer to it on R2/S3/Arweave),
- the **timelocked share** (public-safe — one Shamir share, reveals nothing alone),
- **public keys**: beneficiary recipient, owner signing pubkey, check-in pubkey,
- **timer metadata**: `{owner_id, last_checkin, warn_at, fire_at, status, floor}` —
  timestamps only, **never keys, never plaintext**.

Everything secret stays **client-side / off-platform**, exactly as the single-owner
`init`/`timelock-arm` already enforce by printing-once and writing off-box:

- beneficiary **private** key, owner **signing** key, **check-in** private key,
- the K-1 beneficiary Shamir shares,
- **the raw timelock share** — explicitly **NOT** stored by the platform. The operator
  holds only the *timelocked* blob (one Shamir share, sealed). The raw share is what
  re-locks to a future round, so it stays with the client (§4); parking it server-side to
  enable "convenient" server-side re-arm would hand the operator a real secret and is
  forbidden by design.

The platform is a generalisation of "the host holds only ciphertext," not a new custody
model.

This means **the existing `internal/` packages port almost unchanged** — `vault`,
`shamir`, `timelock`, `custody`, `signing` are all client-side primitives. The platform
adds a *server* that schedules `watch` and stores ciphertext+timers; the crypto stays on
the client.

---

## 4. Liveness integrity — the one genuinely new problem

The operator runs every tenant's timer, so "the timer is honest" is no longer something
the owner controls. Two failure directions, each handled:

- **Suppression (never fires).** The operator stops running a tenant's `watch`. **Fix:
  the drand timelock backstop is mandatory in platform mode, not optional.** Each tenant's
  vault key has one share timelocked to `now + T`. The **client** re-arms on check-in (it
  holds the raw share, off-platform — see below) and uploads the fresh timelocked blob;
  the platform only *stores and serves* it. If the operator goes dark, the last published
  `T` still fires with **no operator and no platform** — the same fail-safe that protects
  the single-owner switch against host death.
- **Premature / forced fire (fires while the owner is alive).** This is the platform's
  sharpest residual, and it is **a real, irreversible, operator-triggered disclosure —
  delayed by ≤ one re-arm window**, not a non-event. The operator cannot *forge* a
  check-in (signed tokens), but it *holds the state* and can refuse to honour a re-arm
  (keep the nearer-`T` share) or poison the stored monotonic floor so valid check-ins are
  rejected — either ages the switch to fire. What bounds the damage: the operator still
  **can't read** the vault, and nothing opens before the drand round. What it does **not**
  bound: once that round arrives the share opens for anyone, permanently. **The only
  defense is detectability** — the client must independently verify the round the
  *actually published* timelock share is locked to (not trust the operator's status API),
  and treat "my re-arms aren't extending the real deadline" as an exit/migrate signal
  (§8). A forced fire is then *detectable in advance* within the window, which is the best
  achievable on infrastructure you don't run.

> **Where re-arm happens (resolved, load-bearing for zero-knowledge):** the **client**
> re-arms, never the platform. Re-arming needs the **raw** timelock share, which per the
> single-owner D5/H7 design is owner-off-box material. If the platform re-armed, it would
> have to hold the raw share server-side — a secret the operator shouldn't have. So the
> client re-locks the same share to a later round locally and uploads only the new
> timelocked blob; the **raw share never reaches the operator.**

The elegant consequence: **the drand timelock that makes the single-owner switch survive
*host* death is the same mechanism that makes the platform survive *operator* malice.**
One backstop, both threats.

---

## 5. Per-tenant isolation & authenticated state (prerequisites, not features)

Before any multi-tenant code, two invariants must hold:

1. **No shared mutable state across tenants.** One logical timer per owner, isolated.
   Cloudflare **Durable Objects** are the natural fit (verified 2026: one DO per tenant,
   single-threaded, tenant-prefixed names, **per-entity alarms** that fire exactly when
   needed — so no shared global scheduler that could cross-fire). One DO = one switch.
2. **Per-owner authenticated state.** Every state mutation that matters (check-in,
   re-arm) is an **owner-signed token** the platform verifies against that owner's stored
   public key. The operator can *drop* state (→ suppression, backstopped) but cannot
   *forge* a newer check-in or a valid older one (monotonic floor). This is the
   single-owner H4+H5 design, applied per tenant.

Without both, H1–H8 don't just recur — they become a **mass** primitive: one bug in the
shared sweep is a cross-tenant disclosure or mass mis-fire. So these are gating
requirements.

---

## 6. Reference architecture (Cloudflare-shaped; portable)

```
  CLIENT (owner's device — holds all secrets, runs the existing dms crypto)
    │  init / seal / timelock-arm happen here; only ciphertext + pubkeys + timelocked
    │  share + signed tokens ever leave the device
    ▼
  EDGE WORKER (stateless API)
    ├── POST /checkin     {owner_id, signed_token}     → routes to the owner's DO
    ├── POST /rearm       {owner_id, timelocked_share} → stores client-produced blob
    │                      (client re-locked it with the raw share; raw never uploaded)
    ├── POST /enroll      {pubkeys, ciphertext ref, timers}
    └── GET  /status      {owner_id}                   (auth'd)
    ▼
  DURABLE OBJECT  (one per owner — isolated timer)
    ├── state: {last_checkin, floor, warn_at, fire_at, status}  (timestamps only)
    ├── alarm(): the per-tenant `watch` tick — warn / fire, no shared scheduler
    └── verifies every check-in token against the owner's checkin pubkey
    ▼
  STORAGE
    ├── R2/S3: vault ciphertext (encrypted to beneficiary; operator can't read)
    └── Arweave: per-owner timelocked share (the no-operator backstop, §4)

  DELIVERY (on fire): email the beneficiary's OWN address + the permanent locator.
                      Never the owner's own accounts (frozen at death).
```

Mapping to what exists: the **engine** (stage/warn/fire/floor), **release**
(Publisher/Notifier), **signing** (token verify), **custody/timelock/shamir/vault** all
move client-side or into the DO's verify path **unchanged in spirit**. The new code is
the Worker API + DO scheduler + per-tenant storage keys — an *operational* layer.

Portability note: the same shape runs on AWS (EventBridge per-schedule + Lambda +
DynamoDB + S3) or a self-hosted server; Durable Objects are the cleanest because
per-entity alarms give true per-tenant scheduling with no shared cron.

---

## 7. H1–H8 per tenant (they multiply — so each must hold at the boundary)

| Hole | Single-owner status | Multi-tenant requirement |
|---|---|---|
| H1 host-holds-ciphertext-only | ✅ | Operator stores only ciphertext+pubkeys per tenant (§3) |
| H2 no key persisted by default | ✅ | Enrollment never uploads private keys; client-side only |
| H3 payload provenance | ✅ | Owner signs vault; beneficiary verifies — unchanged, client-side |
| H4 authenticated state | ⚠️→✅ in platform | **Mandatory** per-tenant signed state + floor (§5) |
| H5 authenticated check-in | ✅ | **Mandatory** in platform (it's how the operator can't forge liveness) |
| H6 idempotent fire | ✅ | Per-DO idempotency key; no cross-tenant publish reuse |
| H7 liveness-coupled timelock | ✅ | **Mandatory** — the backstop against operator suppression (§4) |
| H8 fuse not env-shortenable | ✅ | No env path in the server; thresholds are per-tenant signed policy |

The single-owner work wasn't a detour — it's the **per-tenant security unit** the platform
multiplies. The platform is only as sound as each tenant's switch, and those are now hard.

---

## 8. Honest residuals (what the platform still can't fix)

- **Operator-forced early fire (the sharpest residual — see §2/§4).** The operator holds
  the liveness state and can force an irreversible fire on a live owner within ≤1 re-arm
  window by refusing re-arms or poisoning the floor. It cannot read the vault, and nothing
  opens before the drand round — but the round *will* arrive. **Required client-side
  defense:** the client must verify the **actual published timelock round** of its share
  directly (independent of the operator's status API) and treat re-arms that don't extend
  the real deadline as a migrate/exit trigger. The fire is then detectable in advance,
  inside the window — the best achievable when you don't run the timer. This is strictly
  better than a trusted-operator SaaS (which can also just read your data), but it is a
  real residual, not a non-event.
- **Operator denial-of-service.** The operator can refuse service / delete the convenience
  layer. The drand+Arweave backstop means the *fire* still happens, but the owner loses
  the nag/UX. This is inherent to using someone else's infrastructure; the backstop bounds
  it to "you lose convenience, not the guarantee."
- **Metadata.** Even zero-knowledge, the operator sees *timing* metadata (who checks in,
  when, fire schedules) — a correlation/traffic-analysis surface. Mitigate with uniform
  schedules and unlinkable storage, but timing is hard to fully hide on shared infra.
- **Billing = the operator's lever, and the owner's mortality.** A platform needs revenue;
  a dead owner stops paying. Prepaid multi-year enrollment + the pay-once Arweave backstop
  (so the *fire* doesn't depend on an active subscription) are the only honest answers.
- **Compelled early delivery.** An operator coerced to "fire now" publishes unopenable
  ciphertext (§4) — but if the host-delivery path hands ciphertext to a named beneficiary
  early and that beneficiary also holds their key, the timelock share is the only thing
  still gating. Keep the timelock share as the true gate, not host delivery.
- **All of D3 (quantum/permanence) applies per tenant**, at N× the exposure.

---

## 9. Build sequence (when/if it proceeds)

This is a multi-session build. Suggested order, each independently shippable:

1. **Client `enroll` flow** — extend the CLI to emit an enrollment bundle (pubkeys,
   ciphertext ref, timelocked share, signed initial check-in) without uploading secrets.
   Pure client; testable offline.
2. **DO timer + signed check-in verify** — one Durable Object implementing the engine's
   stage/alarm logic, verifying check-in tokens. The per-tenant security unit.
3. **Worker API + per-tenant storage** — enroll/checkin/rearm/status routes, R2 for
   ciphertext, isolation by DO name. Integration-test cross-tenant isolation explicitly.
4. **Delivery + drand re-arm on the server** — fire path emails the beneficiary's external
   address; re-arm pushes the timelock `T` on each check-in.
5. **Operator-adversary test suite** — assert the operator can't read, can't forge a
   check-in, can't cross-fire; assert suppression still fires via drand.

Do **not** start step 2+ until the §5 isolation/auth invariants are pinned — they are
prerequisites, not features.

---

## 10. Recommendation

The platform is **viable and mostly de-risked** because the single-owner core was built
zero-knowledge from the start. The right next step (if building) is **step 1 — the client
enroll flow** — because it's pure client code, needs no infrastructure, and forces the
enrollment-bundle contract that everything else depends on. Stand up the Durable Object
timer (step 2) only once that contract and the §5 invariants are fixed.

If *not* building now: the single-owner tool + this design doc is a coherent deliverable —
the platform is specified, threat-modelled, and shown to reduce to per-tenant copies of an
already-hardened switch.

---

## Sources

- [Architecting on Cloudflare — Multi-Tenant & Platform Architectures](https://architectingoncloudflare.com/chapter-23/)
- [Cloudflare Durable Objects — Overview](https://developers.cloudflare.com/durable-objects/) · [Rules / best practices](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
- [Cloudflare Dynamic Workflows — durable execution per tenant (2026)](https://blog.cloudflare.com/dynamic-workflows/)
- [The Truth About Zero-Knowledge / Zero-Trust](https://codamail.com/articles/the_truth_about_zero_knowledge_zero_trust.html) — provider-as-adversary ⇒ privacy must live at the endpoints
- Internal: `THREAT_MODEL.md` (§7 + H1–H8), `TIMELOCK.md` (the share-timelock backstop), `HOSTING.md` (the two deaths / second-leg).
