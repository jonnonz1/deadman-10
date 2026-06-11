# deadman-10 — Timelock + Arweave: the no-operator core

A deep design treatment of the two primitives that give a dead-man switch its
"survives everything" property: **drand timelock encryption** (a fire that needs no
host and no human) and **Arweave** (storage that needs no recurring bill). This is an
architecture document — it explains the machinery, the one trap that dominates the whole
design, and the layering that defuses it.

> **The thesis up front.** Timelock encryption is *not confidential* — at the unlock
> time, **anyone** holding the ciphertext can read it. Arweave is **public, permanent,
> and immutable**. Naively combining them publishes your secrets to the world on a timer
> you can never cancel. The correct design **never timelocks the secret** — it timelocks
> a *single Shamir share*, which is useless alone. That one move turns both the
> public-disclosure problem and the re-arm-on-permanent-storage bug into non-events.

---

## 1. Why these two, and what each one actually buys

| Primitive | The single hard problem it solves | What it does **not** solve |
|---|---|---|
| **drand timelock** | Firing with **zero trusted operators** — no server, no human, no account to keep alive. The clock is a global public beacon. | Confidentiality. It is *public-after-T* by construction. |
| **Arweave** | The **recurring-bill death**. Pay once, stored ~200 years. A bill you've fully paid can't lapse when you die. | Privacy (all data is world-readable) and mutability (you can never edit or delete). |

They are complementary on durability and *both wrong on confidentiality* — which is
exactly why the layering in §6 is mandatory rather than optional.

---

## 2. drand timelock — the full mechanism

Timelock encryption sounds impossible: how do you encrypt to a key that *does not exist
yet* and that no one — including you — can compute early? The answer is a beautiful
re-use of three pieces: a distributed randomness beacon, threshold BLS signatures, and
Boneh–Franklin identity-based encryption. Here is the whole chain.

### 2.1 The beacon: a distributed, unbiasable clock

**drand** is a distributed randomness beacon run by the **League of Entropy** — a
coalition of independent organisations (≈15 at launch, **19+ as of 2025**, on four
continents: Cloudflare, EPFL, Protocol Labs, Kudelski, the Ethereum Foundation, the QRL
Foundation, universities, etc.). They jointly emit a fresh, verifiable random value at a
fixed cadence.

The beacon used for timelock is **`quicknet`** (verified live, 2026-06-01):

```
period:        3 seconds        # a new round every 3s
genesis_time:  1692803367       # unix time of round 1
chain hash:    52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971
scheme:        bls-unchained-g1-rfc9380
```

Two properties of that scheme line matter enormously:

- **`unchained`.** Each round's signature is computed over **only the round number** —
  *not* over the previous round's output. This is what makes timelock possible: the
  "identity" of a future round is just an integer you already know, independent of any
  history that hasn't happened yet. (A *chained* beacon signs `previous_signature ‖
  round`, so future identities are unknowable in advance — useless for encrypting to the
  future.)
- **`g1`.** Signatures live in the G1 group (compact), public key in G2. A pairing
  `e: G1 × G2 → GT` is what the IBE in §2.3 runs on.

### 2.2 The key generator nobody controls: threshold BLS

At setup the League ran a **Distributed Key Generation (DKG)**: a master secret `s`
exists only as **shares `sᵢ`**, one per node, such that no node ever holds `s` and `s`
is never assembled anywhere. There is a public master key `PK = s·G₂` that everyone can
see.

Each round `r`, the network produces a **BLS signature over the round number**:

```
σ_r = s · H(r)            # H hashes the integer r to a point on G1
```

It is produced by **threshold signing**: each node `i` publishes a partial signature
`sᵢ·H(r)`; any **`t` of `n`** partials combine (Lagrange interpolation in the exponent)
into the full `σ_r`. Anyone can verify `σ_r` against `PK` with one pairing check. The
*hash* of `σ_r` is the published "randomness," but for timelock the signature `σ_r`
itself is the prize.

The critical timing fact: **the network will not sign round `r` until the wall-clock
time of `r` arrives.** So `σ_r` simply does not exist before time(`r`) — and *cannot* be
computed early without gathering `t` of the `n` shares (i.e. colluding a threshold of the
League).

### 2.3 The binding trick: a BLS signature *is* an IBE private key

This is the conceptual core (Gailly–Melissaris–Romailler, *tlock*, 2023). In
**Boneh–Franklin Identity-Based Encryption**:

- There is a **master public key** and a trusted **Private Key Generator (PKG)** holding
  the master secret.
- You encrypt to an arbitrary **identity string** `ID` (e.g. an email) using only the
  master public key + `ID`. **You do not need any per-recipient key to encrypt.**
- The PKG derives the **private key for `ID`** as `d_ID = s · H(ID)` and hands it to the
  rightful owner, who decrypts.

Now overlay drand onto BF-IBE:

| BF-IBE role | drand equivalent |
|---|---|
| Master public key | the beacon's group public key `PK` |
| Identity `ID` | the **round number `r`** |
| PKG (holds master secret) | the **League of Entropy**, as a *distributed* PKG |
| Private key `d_ID = s·H(ID)` | the BLS signature `σ_r = s·H(r)` |
| PKG "issues the key" | the network **publishes `σ_r` at time(r)** |

So **a BLS signature on a round number is exactly the IBE decryption key for the identity
"that round."** The League is a PKG that issues every identity's private key *on a
schedule*, to *everyone*, automatically. (Note the elegant consequence: the network
needs to know **nothing** about your encryption — no registration, no per-user state. It
just keeps signing integers.)

### 2.4 Encrypt-to-the-future, end to end

1. **Pick the time** `T` and convert to a round:
   ```
   round_for(T) = floor( (T − genesis_time) / period ) + 1
                = floor( (T − 1692803367) / 3 ) + 1
   ```
2. **Encrypt** under BF-IBE with identity `= round_for(T)`, using only the public `PK`.
   In practice this is *hybrid*: a random symmetric file-key is IBE-encapsulated and the
   payload is sealed with it. The `tle` tool emits an **`age`-format file** whose
   recipient stanza is the tlock capsule — so timelock output is just an age file the
   ecosystem already understands.
3. **Wait.** Before `T`, `σ_r` does not exist; the file is opaque to everyone including
   you.
4. **At `T`,** the network publishes `σ_r`. Now `σ_r` is the IBE private key for identity
   `r`: **anyone** holding the file can decapsulate the file-key and decrypt.

No countdown server. No escrow agent. The "timer" is the global beacon, and the act of
firing is the *absence* of any action.

### 2.5 The trust model — stated precisely, because a dead-man switch lives or dies on it

A switch has two asymmetric failure directions. Name them and map each to an assumption:

- **Safety = "it must not open early."** Breaks if a **threshold `t` of `n` League
  nodes collude** to sign round `r` ahead of time, or if the DKG master secret `s` is
  exfiltrated. Mitigation is *organisational*: the ≥19 members span jurisdictions and
  institutions, so early release requires a cross-border conspiracy or a simultaneous
  multi-party compromise. **For a dead-man switch, an early open of the *timelock layer*
  is the dangerous direction — which is precisely why §6 ensures the timelock never
  carries anything that is sufficient on its own.**
- **Liveness = "it must open at `T`."** Breaks if **more than `n − t` nodes are
  offline** (network halts), or the League disbands, or `quicknet` is retired, or the
  pairing scheme is migrated and old ciphertexts are stranded. This is the *durability*
  risk of the fire path. Mitigation: it's a multi-org public good audited by Kudelski and
  running since 2019; still, **never make the timelock the *only* path** — pair it with a
  human-trustee quorum (§6) so a beacon failure degrades to "humans reconstruct" rather
  than "nothing ever fires."

Note the comforting asymmetry: a *liveness* failure means the switch **doesn't fire**
(safe-ish — your secrets stay sealed), while the *safety* failure (early open) is the
scary one — and the layering is built specifically to make an early timelock open
**harmless**.

### 2.6 The property that dominates everything: timelock is *not confidential*

Re-read §2.4 step 4: **anyone** holding the ciphertext can decrypt at `T`. Timelock binds
disclosure to a *time*, not to a *person*. There is no recipient. An adversary who
archived your ciphertext years ago decrypts at `T` exactly when your beneficiary does.

This is not a flaw in tlock — it is the definition of timelock. But it means:

> **A timelocked blob on public storage is a public broadcast scheduled for `T`.**

Everything in §5–§6 follows from taking that sentence seriously.

---

## 3. Arweave — the full mechanism

### 3.1 Pay-once permanence, and why the economics hold

Arweave is a **blockweave**: each block references the previous block *and* a random
"recall" block, and miners must prove access to that recalled history to mine
(*proof-of-access*). The incentive is therefore to store as much of the full history as
possible — replication is a side effect of mining.

Funding is an **endowment**, not a subscription. On upload you pay once;
**~5%** goes to miners immediately and **~95%** enters a decentralised endowment that
pays miners over time. The model is sized for **~200 years** on a deliberately pessimistic
assumption: storage cost declines **just 0.5%/year** (historically it has fallen far
faster — Kryder's law ≈ 30–38%/yr), so the endowment is expected to *outlast* the stated
horizon. Since launch, **no endowment tokens have had to be reissued.**

**Live cost (verified 2026-06-01):** the network price endpoint returns ≈ `9.38×10⁹`
winston per MiB at AR ≈ `$2.23` → **≈ US$0.02 per MiB, one time.** A real deadman vault
is a few kilobytes → **a fraction of a cent, paid once, stored for life.** This single
fact deletes the recurring-bill failure mode from the storage leg.

### 3.2 The three properties — two are gifts, one is a knife

| Property | Why it's good here | Why it's dangerous here |
|---|---|---|
| **Permanent** | The vault can't vanish when you stop paying / die. | A mistake (wrong file, wrong recipient) is permanent too. |
| **Public** | No access infra to maintain; any gateway serves it. | **Anyone can read every byte.** Only ciphertext may go here. |
| **Immutable** | Tamper-evident; the vault can't be silently altered. | You can **never edit or delete**. No retraction, no rotation in place. |

The rule that falls out: **only ever put ciphertext on Arweave, and assume every version
you ever upload is world-visible forever.**

### 3.3 Mutability where you need it: pointers, not edits

You can't edit a transaction, but you can move a **pointer**:

- **ArNS / ANT (Arweave Name System / Name Tokens):** a name you own holds a *mutable*
  pointer to a transaction id. Re-arming/updating = point the name at the new tx. The old
  tx still exists permanently (still ciphertext — still safe), but resolvers follow the
  name to the latest.
- **GraphQL discovery via tags:** every tx/data-item carries **tags**. Tag your uploads
  (`App-Name: deadman-10`, `owner: <hash>`, `version: <n>`) and the beneficiary's tooling
  finds the latest by querying any gateway's GraphQL endpoint — no central index.
- **Bundling (ANS-104) via Turbo:** many "data items" pack into one L1 transaction
  (cheaper, faster, sub-second), each still independently addressable and taggable. Fine
  for our tiny payloads.

So the **vault ciphertext** can be versioned (each version permanent, pointer advances),
while **discovery** is a tag query or an ArNS name — all without any server you run.

### 3.4 The two operational keys people forget

- **An Arweave wallet (RSA JWK)** signs uploads and must hold a little AR. That wallet
  key is itself a long-lived secret to safeguard and (minimally) fund. *It is only needed
  to **write**; readers and the beneficiary need nothing.* Losing it means you can no
  longer update pointers — not that the vault is lost.
- **A gateway to read.** Data is permanent, but a *gateway* must serve it. `arweave.net`
  is the default; you (or anyone) can run an `ar-io` node, and any gateway can serve any
  data. Durability of *retrieval* therefore rests on "≥1 gateway exists," which the
  incentive layer makes near-certain — but the beneficiary instructions should list
  several gateways.

---

## 4. The trilemma: pick the corner deliberately

Three properties a durable dead-man vault wants. **No design gives all three at once** —
the conflict is fundamental, and naming it is what makes the rest principled:

```
                 (1) CONFIDENTIAL to a named party
                      while you are alive
                        /\
                       /  \
                      /    \
   age-to-beneficiary/      \ timelock-only
   + Arweave        /  pick  \  + Arweave
   (1)+(3)         /  a corner \  (2)+(3)
   no auto-fire   /   knowing   \  PUBLIC at T
                 /   the cost     \
                /__________________\
   (2) FIRES with            (3) DURABLE on pay-once
   zero trusted operators        permanent public storage
```

- **age-to-beneficiary + Arweave** → (1)+(3): confidential and durable, but **not
  operator-free** — someone must hold the beneficiary key and *act*. (This is the trustee
  model.)
- **timelock-only + Arweave** → (2)+(3): durable and fires itself, but **public at `T`**
  — the whole world gets your secrets.
- The tempting "**timelock the vault on Arweave**" sits on the (2)+(3) edge and **throws
  away (1)** — it is the public-broadcast footgun.

§6 does not "solve" the trilemma (you can't). It **places a single, minimal, long-lived
secret** with the beneficiary so that the timelock can provide leg (2) without ever being
*sufficient* on its own — buying back (1) for the price of "the beneficiary keeps one
key/share."

---

## 5. Two bugs the naive combination hands you

Before the fix, see clearly what "timelock the vault, store on Arweave" actually does:

### 5.1 Scheduled public disclosure (the confidentiality bug)
At `T`, every archiver on earth decrypts your passwords, recovery codes, and letters.
Because Arweave is **permanent + immutable**, you cannot pull it back even the instant you
realise. A timer you cannot cancel, pointed at the whole internet.

### 5.2 The re-arm time-bomb (the liveness/permanence bug)
The HOSTING.md re-arm model is "on each check-in, re-encrypt to a fresh `T = now +
window`." That assumes you can **replace** the blob. On Arweave you **can't delete the old
one** — and every previously-published blob **still unlocks at its own earlier `T`.**

> Concretely: you publish a 30-day blob in January, stay alive, re-arm with a new 30-day
> blob in February. The **January blob still opens in February** — while you are alive.
> Naive re-arming on permanent storage scatters time-bombs, **the earliest of which fires
> first.** "Push `T` forward" is meaningless when you cannot retract the short-`T` past.

Both bugs share a root cause: **the secret itself is what's timelocked.** Stop doing
that.

---

## 6. The fix: timelock a *single Shamir share*, never the secret

### 6.1 Construction

Layer the encryption so each layer has exactly one job:

```
  payload  ──(symmetric, key MK)──▶  VAULT ciphertext        # goes on Arweave, public-safe
                                       │
  MK  ──Shamir split, K-of-N──▶  shares  s₁ … s_N            # need any K to rebuild MK
                                       │
  distribute the N shares:
    • beneficiary holds            K−1 of them   (offline, long-lived)   ← the minimal secret
    • human trustees hold          spares        (redundancy / quorum)
    • EXACTLY ONE share s*  ──timelock to T──▶  published on Arweave      # the no-operator leg
```

- **The vault** is symmetric ciphertext → safe to be public and permanent.
- **`MK`** (its key) is never stored anywhere whole; it's a **K-of-N Shamir secret**.
- **The beneficiary** permanently holds **K−1** shares. This is the one long-lived secret
  the design requires — and it's why the result can be confidential at all (recall §4: you
  must place *some* secret with a named party).
- **Exactly one share `s*` is timelocked** and published.

### 6.2 Why this defuses *both* bugs at once

**Confidentiality (fixes §5.1).** A lone Shamir share is **information-theoretically
useless** — `K−1` shares reveal *literally nothing* about `MK`. So when the timelock
opens `s*` **to the entire world at `T`**, the world gets *one* share and learns nothing.
Only the party also holding the other **K−1** (the beneficiary) can combine to rebuild
`MK` and open the vault. **Public disclosure of the timelock layer ≠ disclosure of the
secret.** This is the whole trick.

**Re-arm on permanent storage (fixes §5.2).** Re-arming republishes a fresh timelocked
share each cycle. Old published share-blobs still pop at their earlier `T` — **but each
only ever leaks one share to the world, which is useless.** The time-bomb becomes a
dud. Permanence stops being a liability for the firing leg.

> The deep result: **moving from "timelock the secret" to "timelock one share of the
> secret" converts two catastrophic, permanence-amplified failures into harmless
> no-ops** — because a single share carries zero information and the confidentiality now
> rests on the *privately held* `K−1`, which never touch public storage.

### 6.3 What "alive vs dead" means in this model (and an honest limit)

There's a subtlety worth stating rather than hiding. Because you **cannot retract** a
published timelocked share, the beneficiary gains the ability to reconstruct **as soon as
the earliest published `s*` reaches its `T`.** So timelock-on-permanent-storage is **not a
re-armable fast timer** — it is fundamentally a **"set it and it *will* release at `T`"**
backstop. Trying to make it the *short-cycle* liveness signal fights the medium.

Hence the division of labour (consistent with HOSTING.md's *pulse vs. insurance*):

| Leg | Job | Timescale | Medium |
|---|---|---|---|
| **Host `watch` + WARN escalation** (`dms`) | the **fast, recoverable** liveness timer | days–weeks | mutable (host, R2, NAS) |
| **drand timelock share** | the **slow, no-operator backstop** | **long `T`, 6–12 months** | permanent (Arweave) |
| **Human-trustee shares** | recovery if the beacon itself fails | n/a | offline, held by people |

You rotate the backstop **rarely** (e.g. annually: fresh `MK`, fresh split, fresh `s*`
timelocked a year out, pointer advanced). Between rotations the **host path** does the
real work and fires fast *and* recoverably. The timelock only ever actually releases if
the **entire host layer has also been dead for the long `T`** — the genuine "I'm gone"
case. Two independent timescales, each covering the other's failure mode. **Neither leg
has to be both fast and forgiving — which §-appendix of HOSTING.md showed is impossible
for any single timer.**

### 6.4 Rotation and the "stale share" question

When you rotate (`MK → MK'`, new split), shares of the **old** `MK` — including any
world-leaked old `s*` — remain shares of a *different* polynomial for a *different*
secret. They **cannot be mixed** with new shares, and the only complete old set
(beneficiary's `K−1` + the old `s*`) reconstructs only the **old** `MK`, which decrypts
only the **old** vault version. So:

- Re-encrypt the **payload** under each new `MK'` and advance the ArNS pointer to the new
  vault version.
- Old vault versions stay permanently on Arweave but are **ciphertext under a superseded
  key** — exactly as safe as any other archived ciphertext.
- The beneficiary's long-lived holding can be a **stable keypair** that you *re-split
  around* (their identity public key is a fixed "share-holder"), so they never need to be
  re-handed material on every rotation — only the published `s*` and the pointer move.

---

## 7. Discovery: how the beneficiary finds anything

Permanence is worthless if no one can locate the blob in 20 years. Three layers, no
server you operate:

1. **An ArNS name** (e.g. `deadman-alice`) whose pointer always resolves to the current
   vault version. Put the **name** in your will / instructions — not a tx id that will go
   stale on rotation.
2. **GraphQL tag query** as the fallback: `App-Name: deadman-10` + `owner: <hash>` finds
   all versions on any gateway; newest wins.
3. **Printed runbook** with the beneficiary's offline key/share: the ArNS name, 2–3
   gateway URLs, the exact decryption steps, and "you need your `K−1` shares **plus** the
   timelocked share that becomes available after `T`." **Test this runbook with the
   actual beneficiary** — the cypherpunk literature is unanimous that untested recovery
   instructions are the most common point of total failure.

---

## 8. Threat model

| Adversary / event | Outcome under the §6 design | Why |
|---|---|---|
| Internet archiver grabs every Arweave blob | Learns nothing | Vault = ciphertext; timelock leaks ≤1 useless share |
| Timelock opens early (≥`t` League collude) | Learns nothing | Only `s*` (one share) becomes computable; needs `K−1` more |
| Beneficiary key/shares stolen **while you're alive** | Still needs `s*` (locked) **or** `K−1`+`s*` | Below quorum until `T`; rotate immediately if discovered |
| Host(s) seized or destroyed | Switch still fires via backstop | Fire path doesn't depend on your hosts |
| drand network dies (liveness) | Switch doesn't auto-fire; **degrades to trustee quorum** | Human shares reconstruct without the beacon |
| Arweave gateway down | Retrieval via another gateway | Data permanent; many gateways can serve |
| You die; bill lapses everywhere | Backstop + permanent storage unaffected | Nothing left to pay |
| Coercion to reveal **while alive** | Can't — quorum incomplete; you *can* prove you can't yet | The locked `s*` is outside your control until `T` |
| **Quantum (Shor) within the horizon** | **Real long-term risk — see §9** | BLS pairings *and* age's X25519 are quantum-broken |

---

## 9. The honest caveats

- **Quantum + permanence = an unbounded confidentiality window (the sharp rule).** Both
  legs rely on classically-hard problems Shor's algorithm breaks: drand's **BLS pairings**
  and `age`'s **X25519**. A *harvest-now, decrypt-later* adversary archives today's
  ciphertext and opens it once a cryptographically-relevant quantum computer exists —
  *before* your intended `T`. The consequence people miss: this applies to the **vault
  ciphertext itself, not just the timelocked share.** Anything you put on **permanent
  public storage (Arweave) has no expiry on its exposure** — so:
  - **Treat the timelocked *share* as the only thing safe to make permanent + public** — it
    carries zero secret alone (§6.2), so even a full crypto break of the timelock leaks one
    useless share.
  - **Do *not* publish the vault ciphertext to Arweave for secrets that must stay private
    beyond the crypto's lifetime.** Keep the vault on host/mutable storage you can rotate,
    and re-encrypt to a post-quantum recipient when one is standard. Permanent public
    storage is for ciphertext you have *decided* can eventually be world-readable.
  (There is no standard `age` PQ recipient to ship today; this is a deployment rule, not a
  feature — the QRL Foundation joining the League signals drand's own PQ intent.)
- **You cannot un-publish.** Every design decision touching Arweave is one-way. Dry-run on
  testnet / with dummy payloads first.
- **The timelock can't be a fast timer** (§6.3). If you want a fast *and* operator-free
  fire, that's a contradiction on permanent storage — accept the host path as the fast leg.
- **It still rests on a human keeping a secret.** The trilemma (§4) is real: the price of
  buying back confidentiality is the beneficiary safeguarding `K−1` shares for years.
  Lose those *and* you're dead → unrecoverable. Hence trustee redundancy.
- **Re-arm cadence is a real trade** (HOSTING.md appendix): short `T` = tight failsafe but
  unforgiving of outages; long `T` = forgiving but slow. §6.3 resolves it by making the
  backstop long and the host path fast — but you choose the numbers.

---

## 10. Recommended architecture (the synthesis)

```
  WHILE ALIVE                                    AFTER YOU'RE GONE
  ───────────                                    ─────────────────
  dms watch (home box + VPS/serverless)          host stops checking in
    │  fast timer, days–weeks                       │
    │  WARN → escalate → (recoverable) fire         │  WARN escalates, no response
    ▼                                               ▼
  rotate annually:                               PRIMARY: host fire delivers pointer+share
    • fresh MK, K-of-N Shamir split              BACKSTOP: at long-T, drand publishes σ_r
    • re-encrypt vault, advance ArNS pointer       → timelocked s* becomes available
    • timelock ONE share s* to now+12mo            → beneficiary combines s* + their K−1
    • publish vault (ciphertext) + s* to Arweave   → rebuilds MK → opens vault
                                                   FALLBACK: beacon dead? trustees' shares
                                                             reach quorum without drand
```

- **Confidentiality:** always the inner `age`/symmetric layer to a Shamir quorum. Never
  expires, never public.
- **No-operator fire:** the single timelocked share — public-safe, permanence-safe.
- **Durability:** pay-once Arweave for the ciphertext + ArNS pointer for discovery.
- **Anti-fragility:** three independent ways to reach quorum (host delivery, timelock
  backstop, human trustees); no single one is load-bearing.

This is the version that survives your death, the host's death, the bill lapsing, a
gateway outage, an early timelock open, *and* a beacon failure — while never broadcasting
your secrets to the world.

---

## Sources

- [tlock: practical timelock encryption from threshold BLS (IACR ePrint 2023/189)](https://eprint.iacr.org/2023/189.pdf)
- [drand — Timelock Encryption docs](https://docs.drand.love/docs/timelock-encryption/)
- [drand/tlock (`tle` CLI)](https://github.com/drand/tlock)
- [Timelock Encryption now on drand mainnet](https://docs.drand.love/blog/2023/03/28/timelock-on-fastnet/)
- [League of Entropy — Wikipedia](https://en.wikipedia.org/wiki/League_of_Entropy) · [drand LoE page](https://www.drand.love/loe/)
- [NIST STPPA7 — Timelock Encryption overview & retrospective (2025)](https://csrc.nist.gov/presentations/2025/stppa7-timelock-encryption)
- [Arweave — Pay Once, Store Forever](https://www.arweave.com/blog/permanent-storage-on-arweave) · [Endowment explained](https://permaweb-journal.arweave.net/article/storage-endowment-explained.html)
- [ArNS — Arweave Name System](https://docs.ar.io/build/guides/arns) · [ANS-104 bundles](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md)
- [Lopp — *Fifteen Men on a Dead Man's Switch*](https://blog.lopp.net/fifteen-men-on-a-dead-man-s-switch/) (trustee/SSS + testing discipline)
- Live values verified 2026-06-01: `arweave.net/price/1048576`, `api.drand.sh/<quicknet>/info`
