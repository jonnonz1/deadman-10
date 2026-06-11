# deadman-10 — Threat & Risk Model

> **Scope.** The Go implementation at HEAD on 2026-06-03, *including* the durable
> no-operator custody path that is now wired: `cmd/dms` (`quickstart`, `init`,
> `seal`, `checkin`, `watch`, `fire`, `verify`, `timelock-arm`,
> `timelock-recover`, `recovery-card`) and `internal/{vault,engine,keys,release,
> config,shamir,timelock,custody,recoverycard}`. Build is green, `go vet` clean.
> The repository was **actively changing during this analysis** (the `verify`
> plaintext-temp leak was fixed mid-review; the custody/timelock commands landed),
> so this models the tree as read, and §12 lists what would invalidate it.
>
> This is a decision aid, not an audit sign-off. It models what the **code does
> today** and flags where the code **contradicts or lags** the security
> properties the docs already claim.

---

## 0. How to read this document

A dead-man switch is not a normal confidentiality system, so a STRIDE checklist
mis-prioritises it. The organising principle is **§2: the central tension** —
every control trades one catastrophic failure mode against the other. Read that
first; the catalogue (§6) hangs off it.

Findings are split into two visually distinct buckets so the signal isn't buried:

- **🆕 NEW** — holes the design docs (`README.md`, `HOSTING.md`, `TIMELOCK.md`)
  do *not* currently name. These are the "gaping holes." There are **eight** (§1).
- **✓ ACKNOWLEDGED** — risks the docs already call out, listed for completeness
  and formalised with a rating, not presented as news.

Risk is rated on **likelihood × reversibility**, not generic severity — in this
system the only impact axis that matters is *can you undo it* (§5).

---

## 1. TL;DR — the holes that matter

| # | Hole | Failure mode | Reversibility | Status |
|---|------|--------------|---------------|--------|
| **H1** | ~~**"The switch only ever holds ciphertext" is false.**~~ **✅ FIXED (2026-06-04).** The owner is no longer an encryption recipient (recipients file = beneficiary only) and no owner decryption key is written to the host. `init`/`quickstart` print private keys once and persist only public halves (`beneficiary.pub`, `owner-sign.pub`). Proven by `TestCLIHostHoldsNoPrivateKeys`. Trade: the owner can no longer self-recover from the host vault while alive — keep the beneficiary key (or an offline copy) for that. | Confidentiality | ~~live leak~~ → mitigated | ✅ FIXED |
| **H2** | ~~**`quickstart` persists the beneficiary private key on the host by default.**~~ **✅ FIXED (2026-06-04).** `quickstart` now prints the beneficiary + owner-signing private keys once and persists neither (unless `--dev`). Proven by `TestCLIQuickstart` (asserts no `keys/beneficiary.key`). | Confidentiality | ~~Hard~~ → mitigated | ✅ FIXED |
| **H3** | ~~**No payload provenance.**~~ **✅ FIXED (2026-06-04).** `seal`/`quickstart` sign the vault ciphertext with an offline owner Ed25519 signing key (`internal/signing`), writing `vault.age.sig`; `verify` checks it against `owner-sign.pub` (or `--owner-sign-pub` from the recovery card) and refuses a forged/tampered vault. Signing is at-seal, verification at-recovery — neither needs a host secret. Proven by `signing.TestForgeryDetected` + `TestCLIForgedVaultRejected`. | Integrity | ~~Irreversible~~ → detectable | ✅ FIXED |
| **H4** | **Unauthenticated liveness state.** ⚠️ **PARTIALLY MITIGATED (2026-06-04).** Added a **monotonic check-in floor** + **future-date clamp** in the engine: a rolled-BACK `last_checkin` is ignored (the floor holds), and a future-dated stamp can't manufacture extra life (elapsed clamped ≥0). This kills clock-skew, NTP games, naive rollback, and accidental corruption — proven by `engine.TestRollbackUsesMonotonicFloor` / `TestFutureDatedCheckinDoesNotExtendLife`. **NOT a full fix:** on a single-binary host the floor/state have no MAC a same-uid attacker lacks (any key would sit beside the state it protects — the very flaw H1 names). A determined local attacker who rewrites both `last_checkin` and `checkin_floor` still wins. The real answer to "malware owns the timer" is the §2 independent-leg layering, not a host-resident hash. | Both | Fire is irreversible | ⚠️ partial |
| **H5** | **Check-in proves nothing about *who*.** ✅ **AUTH HALF FIXED (2026-06-04); duress deferred.** `init --auth-checkin` provisions an owner check-in key; the host keeps only the PUBLIC half, and `dms checkin --checkin-key` submits a **signed token** the engine verifies (`engine.AuthCheckin`) before accepting proof of life. A process without the owner key can't forge a check-in → can't silently suppress (verification is asymmetric, like H3). The token covers the timestamp and is rejected if older than the monotonic floor (replay protection) — this also **upgrades H4 from partial to real** when auth check-in is enabled. Proven by `signing.TestForgedTokenRejected`, `engine.TestAuthCheckin*`, `TestCLIAuthCheckinRequiresKey`. **Residual:** if check-in is run *on* the watch host with the key present, malware at check-in time can capture it (the strong form produces the token off-host). **Duress signal deliberately deferred:** on a single host with an unreliable channel, fire-on-duress *is* the irreversible disclosure we avoid, and a flag-in-a-file nobody reads is theater — not shipped rather than shipped-as-theater. | Failure-to-fire | Silent | ⚠️ auth fixed; duress deferred |
| **H6** | ~~**Re-publish on partial fire.**~~ **✅ FIXED (2026-06-03).** Fire is now transactional: the engine writes a `firing` intent record before publishing, and every publisher is wrapped in `release.Idempotent`, which keeps a durable receipt keyed by a stable per-fire `publishID` and **never re-uploads** an already-published fire — across crashes and restarts. Proven by `engine.TestFireRetryDoesNotDoublePublish` and `release.TestIdempotent*`. | Integrity / cost | ~~Irreversible~~ → mitigated | ✅ FIXED |
| **H7** | ~~**The durable timelock leg is not liveness-coupled.**~~ **✅ FIXED (2026-06-04).** Added `custody.ReArm` + `dms timelock-rearm`: it re-timelocks the **same** share to a later round (the owner supplies the raw share via `--raw-share`; it is **not** kept on the host — see D5), so the deadline tracks check-ins **without** regenerating the key — already-distributed beneficiary shares stay valid. The permanent-storage trap is now encoded: the share must stay on **mutable** storage (the constraint is documented in `custody.ReArm`'s doc and warned at `timelock-arm`), since an un-retractable Arweave blob would fire on a calendar. Proven by `custody.TestReArmKeepsSharesValid` + live `TestCLITimelockReArm`. | Premature disclosure | ~~Irreversible~~ → mitigated (with storage constraint) | ✅ FIXED |
| **H8** | **The fuse is shortenable from the environment.** ⚠️ **ACCIDENT-PROOFED (2026-06-04).** `DMS_*_MINUTES` env overrides now take effect **only** with an explicit `--demo` flag (`config.ApplyEnvOverrides(demo)`); a stray/leftover/injected env var is ignored in production, so it can't silently arm a hair-trigger. Proven by `TestCLIEnvFuseIgnoredWithoutDemo` + `config.TestEnvOverrideOnlyInDemo`. **Not a defence against a deliberate local attacker** — anyone who can set env can pass `--demo` or edit `config.json` directly (same single-host boundary as H4); this removes the *accident*, not the adversary. | Premature fire | Irreversible | ⚠️ accident-proofed |

Everything else (single-host SPOF, frozen channel, key-over-decades, `--dev`,
Arweave permanence, drand trust, share co-location) is real but **already
acknowledged** in the docs — formalised in §6 / §8, not re-litigated.

---

## 2. The central tension (the architectural spine)

A dead-man switch has **two failure modes that are catastrophic in opposite
directions**, and no single knob minimises both:

```
        FALSE POSITIVE                         FALSE NEGATIVE
   "fires while you're alive"             "never fires when it should"
   → irreversible disclosure             → purpose fails, silently
   (vacation, lost phone, clock           (host dies, cron disabled,
    skew, malware, coerced fire,           wrong cwd, bill lapses,
    fixed-time timelock unlock)            state corrupt/inert)
            ▲                                       ▲
            │   longer thresholds,                  │   auto-fire timelock,
            │   confirmation gates,                 │   any-leg-fires quorum,
            │   suppression-resistance              │   short thresholds
            └────────────  PULL APART  ─────────────┘
```

**Every mitigation for one mode worsens the other.** Make it harder to fire by
mistake (longer warn window, human confirmation, resist coerced/forged
check-ins) and you make it more likely to *never* fire. Guarantee it fires
(timelock self-open, aggressive thresholds) and you raise the odds it fires
while you're on a beach with no signal — H7 is exactly this trap: the durable
leg guarantees an open, but at a *fixed wall-clock time* decoupled from life.

The asymmetry that breaks the tie is **reversibility**:

- A **false positive is irreversible** — once the vault reaches a beneficiary
  (worse, a *public permanent* store) it cannot be recalled. The WARN window is
  the only undo, and it rides a best-effort notifier (§6-B5).
- A **false negative is silent** — discovered only at the moment of need, when
  the owner is by definition unavailable to fix it.

The only escape is **layered, independent mechanisms on different timescales**
so no single failure causes either mode — the "two deaths" framing in
`HOSTING.md` and the custody ladder in `README.md`. The point of this model is
that the wiring is now *half-built*: the durable leg exists (`timelock-arm`) but
is **not coupled to liveness** (H7), and the default leg is still **one host,
one tick, one unauthenticated file** (H4/H5/C1) between both catastrophes.

---

## 3. Assets

| Asset | Why it matters | Where it lives today |
|-------|----------------|----------------------|
| **Vault plaintext** (the secret) | The thing being protected | `secrets/` pre-seal; inside `vault.age` post-seal |
| **Beneficiary private key** | Sole capability to open a simple-mode vault | Printed once at `init`; **on disk after `quickstart`/`--dev`** (H2) |
| **Owner private key** | *Also* opens the vault (owner is a recipient) | `keys/owner.key` on the host — see H1 |
| **Shamir shares** (timelock mode) | K together = the vault key | `share-*.txt` / `share-timelocked.age`, written to repo root (D5) |
| **Liveness state** (`last_checkin`, `fired`, `nags`) | Decides whether the switch fires | `state/` plaintext files on the host |
| **Policy** (`config.json`, `DMS_*` env) | Thresholds, recipients, storage, webhook | `config.json` + process env |
| **The fire decision** | Irreversible; the whole point | `engine.Watch()` per tick; `timelock` round |
| **Delivery channel** | Must outlive the owner | Notifier (local / webhook / stdout) |

---

## 4. Trust boundaries & adversaries

```
 ┌─────────────────────────── OWNER'S HOST (one box) ───────────────────────────┐
 │ config.json · DMS_* env · keys/owner.key · keys/beneficiary.key(!) · vault.age │
 │ state/* · share-*.txt · the dms binary · the scheduler that calls `dms watch`  │
 └───────────────┬───────────────────────────────────────────────┬──────────────┘
                 │ notifier (webhook/local)                        │ publisher (file/Arweave)
                 ▼                                                 ▼
        Slack / email / OS                              outbox/ → (future) Arweave (PUBLIC, PERMANENT)
                                                                   │
   drand quicknet (api.drand.sh) ── timelock leg (now wired, fixed-T) ── beneficiary (offline shares)
```

| Adversary | Capability | In scope? |
|-----------|------------|-----------|
| **Host-local user / malware** | Read+write the working dir as the owner's uid | **Yes** — primary. Owns keys, state, config, shares, vault. |
| **Full host compromise** | Root on the box | **Yes** — H1/H2 make this *plaintext* disclosure, not "leaks nothing." |
| **Coercion adversary** ("rubber-hose") | Forces continued check-in, or reveal of offline shares | **Yes** — H5. No duress path exists. |
| **The beneficiary** | Holds the open capability; may want it *early* | **Yes** — H7 hands it to them at a fixed time regardless of death. |
| **Anyone who learns `beneficiary.pub`** | It is public by design | **Yes** — H3 forgery. |
| **Network MITM** | Intercept webhook / drand HTTPS | Partial — drand chain hash is pinned (good); webhook TLS unvalidated. |
| **Infra operators** (drand LoE, Arweave, cloud) | Run the no-operator backstops | **Yes** — liveness + collusion (§6-D). |
| **Platform operator** (future multi-tenant) | Runs *everyone's* timer | **Scoped/future** — implied by the stated goal, not yet in code (§7). |
| **Future cryptanalysis / quantum** | Harvest-now-decrypt-later | **Yes** for permanent public storage (§6-D3). |

---

## 5. Risk rating method

**Likelihood** — how plausibly this occurs in normal operation or under a
realistic adversary. **Reversibility** is the impact axis (not severity):

| Reversibility | Meaning |
|---|---|
| **Irreversible** | Cannot be undone (disclosure delivered; permanent upload; coerced reveal) |
| **Hard** | Recoverable only with manual, lossy, or out-of-band effort |
| **Recoverable** | Local, undoable, no lasting harm |

Combined **Risk = Critical / High / Medium / Low**, weighting irreversibility
heavily.

---

## 6. Threat catalogue

### A — Confidentiality / premature disclosure

| ID | Threat | Code / evidence | Likelihood | Reversibility | Risk | Status |
|----|--------|-----------------|------------|---------------|------|--------|
| **A1** | **Plaintext-equivalent on the host.** `init`/`quickstart` make the owner a recipient (`commands.go:44`, `quickstart.go:55,57`) and write `owner.key` beside `vault.age` (`commands.go:41`). Anyone who reads the host decrypts now — no fire, no wait. Falsifies README:18,35 / HOSTING:18-20 ("host only ever holds ciphertext / full compromise leaks nothing readable"). | `commands.go:41,44` | Med (host compromise / backup leak / shared box) | live | **Critical** | 🆕 **H1** |
| **A2** | **`quickstart` writes `beneficiary.key` to disk unconditionally** (`quickstart.go:53`) — not gated behind `--dev`. The friendly default leaves *both* private keys + ciphertext on one box; the printed "give it to your beneficiary, store OFFLINE" never removes the local copy. The setup the docs steer newcomers to is the one that breaks custody. | `quickstart.go:53,81` | High (anyone using quickstart) | Hard | **High** | 🆕 **H2** |
| **A3** | **Premature fire = irreversible disclosure.** One threshold crossing on one box delivers the secret. Triggers: clock skew, missed check-ins on holiday, short threshold, malware, coercion. | `engine.go:118-126,151-168` | Med | Irreversible | **High** | ✓ (README:92,104) |
| **A4** | **Timelock unlock is fixed-time, not liveness-coupled.** `timelock-arm` seals one share to a fixed round ~1 yr out (`timelock_cmds.go:28,37-38`); nothing re-arms on check-in. At that round the share is public and the beneficiary (holding K-1) can reconstruct — **alive or dead**. Re-arming to push the date out regenerates the ephemeral key (`custody.go:55`), invalidating already-distributed shares, so periodic refresh is operationally broken. | `timelock_cmds.go:28,37-38`, `custody.go:46-91` | Med | Irreversible | **High** | 🆕 **H7** |
| **A5** | **Arweave permanence ⇒ infinite confidentiality window.** Once published, ciphertext is public + permanent; secrecy then rests *entirely* on the beneficiary capability never leaking, forever. Default `dry_run=true` and the real uploader is unwired (`main.go:91-106`), so latent today, but it is the intended end-state. | `config.go:53`, `main.go:91-106` | Low today / High at GA | Irreversible | **High (latent)** | ✓ (TIMELOCK.md) |
| **A6** | **`--dev` keeps the beneficiary key on disk** (`commands.go:46`) — same custody collapse as H2 but opt-in; H2 makes it the default. | `commands.go:46`, README:107 | Med | Hard | **Medium** | ✓ |
| **A7** | **Single beneficiary capability, no rotation.** Rotating keys orphans the vault (`commands.go:29-32`); a leaked/compelled beneficiary key/shares is total, permanent compromise on a public store. | `commands.go:29-32` | Low–Med | Irreversible | **Medium** | ✓ (README:101) |

### B — Integrity, provenance & state tampering

| ID | Threat | Code / evidence | Likelihood | Reversibility | Risk | Status |
|----|--------|-----------------|------------|---------------|------|--------|
| **B1** | **No payload provenance / forged vault.** `Seal` encrypts *to* recipients with no sender signature (`vault.go:32`); `beneficiary.pub` is public and sits in `recipients.txt`. Anyone who learns it can craft a `vault.age` that decrypts cleanly and that the beneficiary trusts as the owner's last word (testament, credentials, evidence). Host pre-substitution is the easy path; the beneficiary has **no way to detect** it. | `vault.go:21-52`, `commands.go:44` | Med | Irreversible once delivered | **High** | 🆕 **H3** |
| **B2** | **Unauthenticated liveness state.** `last_checkin` is parsed from a plaintext file with no MAC (`engine.go:92-100`); stage is just `now − last` (`engine.go:113-126`); `fired` is mere file existence (`engine.go:129-132`). Roll `last_checkin` back → instant fire; touch forward → suppress; delete `fired` → re-fire; create `fired` → never fire; delete `last_checkin` → revert to UNKNOWN and the switch goes inert. The engine writes `0600`, but nothing *binds* state to the owner, so any local write wins. | `engine.go:77-132` | Med–High (local user, malware, FS corruption) | Fire-side irreversible | **High** | 🆕 **H4** |
| **B3** | ~~**Re-publish on partial fire.**~~ **✅ FIXED (2026-06-03).** `Watch` now writes a `firing` intent record before releasing, and the publisher is wrapped in `release.Idempotent` (`main.go:80-83`, `idempotent.go`): a durable receipt keyed by a stable per-fire `publishID` means a crash after publish but before `fired` does **not** re-upload on the next tick. Verified: `engine.TestFireRetryDoesNotDoublePublish` (crash→retry→exactly one upload), `release.TestIdempotentSurvivesRestart`. | `engine.go:146-178`, `release/idempotent.go` | Med | ~~Irreversible~~ → mitigated | ✅ **H6 FIXED** |
| **B4** | **Unprotected policy + shortenable fuse.** `config.json` is plain JSON (`config.go:84-90`) and `DMS_FIRE_AFTER_MINUTES` is applied on every load (`config.go:94-105`, `main.go:66`). `fire_after_minutes:0` or the env var fires on next tick. Any local write / env-setting process owns the fire decision. | `config.go:84-105`, `main.go:66` | Med | Irreversible (fire) | **Medium** | 🆕 **H8** |
| **B5** | ~~**Notifier non-delivery is silent (the undo path fails open).**~~ ✅ **FIXED (2026-06-04).** `WebhookNotifier` now treats **non-2xx as failure** and **retries** (3 attempts, linear backoff), returning a loud error the WARN path surfaces — the brake no longer fails silently. Crucially, the FIRE notification is **logged-not-fatal** in `Releaser.Release`: gating fire completion on notify success would turn a dead webhook into a suppression/duplication vector, so notification is best-effort *after* the irreversible publish. Proven by `TestWebhookNon2xxIsError`, `TestWebhookRetriesThenSucceeds`, `TestReleaseSucceedsDespiteNotifyFailure`. Residual: still needs a beneficiary-controlled external channel (C4) — louder, not omniscient. | `notifiers.go`, `release.go` | Med | Hard (missed window) | ✅ FIXED (channel residual) |

### C — Availability / failure-to-fire (the silent mode)

| ID | Threat | Code / evidence | Likelihood | Reversibility | Risk | Status |
|----|--------|-----------------|------------|---------------|------|--------|
| **C1** | **Single host = single point of failure (default leg).** `watch` is *one tick*; the timer is whatever external cron/launchd/systemd calls it. Box dies / bill lapses / scheduler disabled → never fires, **silently**. ⚠️ **DEPLOYMENT-SCOPED (2026-06-04):** this is not a code hole — the `timelock-arm` backstop (now liveness-coupled, H7-fixed) *is* the second leg that needs no host of yours, and HOSTING.md §10 documents the rule: run `watch` on ≥2 hosts with absolute `--dir`, lean on the timelock backstop, and external-healthcheck the watcher. A built-in watcher-of-the-watcher is deliberately not built (infinite regress). | HOSTING.md §10 | High over long horizons | Silent | ⚠️ deployment-scoped (timelock = 2nd leg) |
| **C2** | **Check-in requires no proof of the owner.** `Checkin` stamps a file (`engine.go:77-88`); any process/cron/attacker that runs it is a valid heartbeat. Malware or coercion suppresses the switch indefinitely; there is **no duress signal** and nothing only the living owner can produce. | `engine.go:77-88` | Med | Silent | **High** | 🆕 **H5** |
| **C3** | **Working-directory footgun.** `paths()` resolves config + state against `os.Getwd()` (`main.go:54`). A cron/systemd unit without an explicit `WorkingDirectory` runs from `/` or `$HOME` → reads no config/state → defaults + empty state → `StageUnknown` → `Watch` does nothing → **never fires, silently**. This is the canonical way cron-driven tools die. | `main.go:53-57` | Med–High (misconfigured scheduler) | Silent | **High** | 🆕 |
| **C4** | **Clock dependence, no sanity guard.** Stage is wall-clock arithmetic over `time.Now()` (`main.go:21`, `engine.go:104-109`). NTP attack, VM drift, or a manual clock change fires early or never; a future-dated `last_checkin` is accepted. No monotonic floor, no skew check. | `engine.go:104-126` | Low–Med | Fire-side irreversible | **Medium** | 🆕 |
| **C5** | **Frozen delivery / unreachable beneficiary.** A Slack-to-self or owner's-own-email channel is dead once accounts close; the beneficiary may never receive or may lose their key/shares over decades. | `notifiers.go`, README:98-103 | Med | Hard | **Medium** | ✓ |
| **C6** | **Resource-exhaustion denial of fire.** `Release` reads the whole vault into memory (`release.go:41`); a large vault or full disk fails the publish/`fired` write and (via B3) loops. | `release.go:40-48` | Low | Recoverable | **Low** | 🆕 (minor) |

### D — Infrastructure, permanence & long-horizon

| ID | Threat | Code / evidence | Likelihood | Reversibility | Risk | Status |
|----|--------|-----------------|------------|---------------|------|--------|
| **D1** | **drand trust (two-sided).** The timelock leg trusts the League of Entropy for *liveness* (beacon stops → timelocked share never opens → recovery false-negative) and *non-early-publish* (a threshold colluding could unlock early). Fetched over HTTPS from `api.drand.sh` (availability/MITM), though the **chain hash is pinned** (`timelock.go:20-21`) — good. | `timelock.go:55-62`, TIMELOCK.md | Low | Mixed | **Medium** | ✓ |
| **D2** | ~~**Metadata leakage on release.**~~ ✅ **FIXED (2026-06-04).** The Arweave publisher tags transactions with only `Content-Type: application/octet-stream` — no `deadman-10`/app tag — and `Release` passes `nil` tags, so a published blob carries no "owner presumed dead" signal. Residual (note, not engineered): the *notification body* names the locator, which is fine for a private webhook but would beacon "ciphertext here" if that channel were ever public — keep the notify channel private. | `arweave_publisher.go:46-49`, `release.go` | Low | Irreversible (public) | ✅ FIXED (private-channel residual) |
| **D3** | **Harvest-now-decrypt-later.** ⚠️ **DOCUMENTED (2026-06-04), no code fix — there is no standard age PQ recipient to ship.** age X25519 on a *permanent public* store gives an **unbounded** confidentiality window: any future X25519 break / CRQC retroactively exposes everything ever published. The sharp design rule (now in TIMELOCK.md): this applies to the **vault ciphertext on Arweave, not only the timelocked share** — permanent public storage is for ciphertext you've *decided* can eventually be world-readable. Don't publish the vault to Arweave for secrets that must stay private beyond the crypto's lifetime; keep those host/mutable-only and treat the timelock share (which carries no secret alone) as the sole permanent-public element. | A5 + age | Low now | Irreversible | **Medium (long-horizon)** — accepted/documented | ✓ |
| **D4** | **Supply chain / binary integrity.** ⚠️ **PARTIALLY ADDRESSED (2026-06-04).** Stale premise corrected: `goar` was **eliminated** — the Arweave client is stdlib-only and a `go list -deps` audit confirms **no go-ethereum/gorm/goar/hashicorp-vault** in the binary, shrinking the supply-chain surface materially. Reproducible builds documented (`-trimpath`, pinned Go toolchain via `go.mod`) in BUILD.md. **Release signing deferred:** there is no published repo to attach a cosign/minisign pipeline to yet (the repo doesn't exist by the owner's instruction); a swapped binary still defeats everything until signed releases exist. | `go.mod`, `BUILD.md` | Low | Hard | ⚠️ surface reduced; signing deferred |
| **D5** | ~~**`timelock-arm` co-locates all K shares on the host.**~~ **✅ FIXED (2026-06-04).** `timelock-arm` now keeps **only** `share-timelocked.age` (safe alone) in the switch home; the raw share and the K-1 beneficiary shares are written to a separate `MOVE-OFFBOX-then-delete/` directory with a loud warning to move them off the host. `timelock-rearm` takes the owner-supplied `--raw-share` (not stored on the host), and `timelock-recover` reads beneficiary shares from `--shares-dir`. The host therefore never holds a K-of-N subset. (This also closed the `share-raw.local` hole H7's first cut introduced.) Proven by `TestCLITimelockArmNoKeySubsetOnHost`. Residual: the tool can't *force* the human to actually move the off-box dir — it warns and separates, but custody discipline is still the owner's. | `timelock_cmds.go` | Low (was Med) | Irreversible (after round) | ✅ FIXED (human-discipline residual) |

### E — Lower-tier / completeness (noted, not headline)

- **`fire --force` is unauthenticated** (`commands.go:144-156`) — any local user fires; subsumed by H4/H8 (local write already wins).
- **Recovery card leaves data locators blank** (`recoverycard.go:74-79`) — a beneficiary can receive a card with no actual location of the ciphertext/share; an operational TODO, not a code bug.
- **State-format drift** — on-disk `state/` also holds `stage` + `notifications.log` from the Python reference, not the Go engine; a consistency smell, harmless.

---

## 7. The platform adversary (scoped — implied by the goal, not yet in code)

The stated goal is *"many independent owners = a platform."* `HOSTING.md`
sketches one Cloudflare Cron Worker iterating **every owner's timer**
(HOSTING:219,263). That introduces an adversary the current single-dir trust
model has no answer for:

- The **platform operator is trusted-for-liveness for all tenants** — it can
  suppress (never fire) or trigger (fire early) *any* owner's switch, and sees
  every owner's timer metadata.
- **Tenant isolation is unspecified** — one owner's state/config/shares must not
  be readable or writable by another, and a bug in the shared sweep must not
  cross-fire.
- H1–H8 **multiply per tenant**: unauthenticated state, a shortenable fuse, and
  on-box keys are bad on one box; as a multi-tenant service they are a
  mass-disclosure primitive.

**Action:** before any multi-tenant work, redraw §4 with the platform operator
as an explicit, partially-untrusted party, and make per-owner state
authenticated (ties to H4/H5) so the operator cannot silently rewrite a timer.

**→ Now specified in [`PLATFORM.md`](PLATFORM.md) (2026-06-04).** Key results:
confidentiality and check-in *forgery* are fully closed by the zero-knowledge +
signed-token design (operator stores only ciphertext + public keys + a single
sealed share); suppression is backstopped by the client-re-armed drand timelock.
**The sharpest residual: an operator that holds the liveness state can FORCE an
irreversible early fire on a live owner within ≤1 re-arm window** (refuse re-arms,
or poison the monotonic floor) — signed tokens stop forgery but not the operator
dropping/poisoning state it holds. It can't *read* the vault and nothing opens
before the drand round, but the round will arrive. Mitigation is **client-side
detectability**: verify the *actually published* timelock round independently of
the operator and migrate if re-arms aren't landing. Re-arm happens **client-side**
(raw share never reaches the operator). See PLATFORM.md §2/§4/§8.

---

## 8. Risk heat map

```
 REVERSIBILITY →     Recoverable      Hard               Irreversible / Silent
 LIKELIHOOD ↓
 High                                 A2                 C1  C2·H5  C3
 Medium              C6               A6 B5 C5 D5         H1·A1  H2 H3·B1  H6·B3  A3 A4·H7 A5 B4·H8 D2
 Low                                  D4                 C4  D1  D3  A7
```

Top-left is benign; **bottom-/rightward toward "irreversible / silent" is where
a dead-man switch dies**. The 🆕 cluster (H1–H8) along the right edge is the
answer to *"where are the gaping holes."*

---

## 9. What the design already gets right (don't regress these)

- The **custody shape is correct in principle** (encrypt to a key the switch
  never holds). H1/H2 are *deployment* violations of a good design, not flaws in
  the design itself.
- The **share-timelock construction** (`internal/custody`) faithfully implements
  TIMELOCK.md: one share timelocked, the ephemeral key **never written whole**
  (`custody.go:44-59`), and a **below-threshold guard** that rejects the junk
  Shamir returns under K (`custody.go:131-134`). The *math/structure* is sound;
  the holes are operational (A4, D5).
- The **recovery-card generator** (`internal/recoverycard`, `recovery-card`,
  auto-written by `timelock-arm`) directly attacks the literature's #1 failure
  mode — missing/unclear recovery instructions. Good and rare.
- **`verify` no longer leaves plaintext on disk** (`commands.go:175` cleans the
  temp dir; `--out` persists only on explicit request).
- **`vault` refuses non-regular files** on seal and unknown entries on extract
  (`vault.go:111-114,170-175`) → no silent partial recovery; **zip-slip blocked**.
- **drand chain hash pinned**; **Shamir uses `crypto/rand`** with a tested K−1
  leak property; **`init --force` refuses to orphan a vault**; **non-dry-run
  Arweave refuses** rather than no-op-firing (`main.go:100`).
- `HOSTING.md` / `README` already name SPOF, silent death, false fire, the bill,
  the frozen channel, and key-over-decades. The gap is **code lagging design**,
  not blind spots in the design.

---

## 10. Prioritised remediation roadmap

**P0 — close the live / irreversible holes before this protects anything real**

1. **H1 / H2 — stop putting open-capability on the watching host.** Drop
   `owner.pub` from recipients (or keep the owner recovery identity *offline*),
   and make `quickstart` print the beneficiary key once like `init` instead of
   persisting it. Then the "ciphertext-only" claim becomes true; fix README:18,35
   to whatever you choose.
2. **H4 — authenticate liveness state.** MAC `last_checkin`/`fired` with a key the
   casual local attacker lacks, reject future-dated check-ins, add a monotonic
   floor (C4).
3. **H3 — sign the payload.** Owner-signs the sealed payload (minisign / ssh-sig);
   `verify` and the recovery card check it, so a substituted/forged vault is
   detectable.
4. **H6 — make fire transactional & idempotent.** Record intent before publish,
   key `fired` to a publish-id, never re-publish a published fire — *before*
   wiring any irreversible backend.
5. **H7 — couple the timelock to liveness, or label it honestly.** Either re-arm
   on check-in with a stable (re-usable) key so the unlock round actually tracks
   life, or document that `timelock-arm` is a fixed-date capsule and not a
   dead-man trigger. As written it discloses on a calendar, not on death.

**P1 — close the silent / suppression holes**

6. **H5 — make check-in prove the owner** (a secret/signed check-in, or an
   out-of-band heartbeat the beneficiary can observe), and add a **duress
   check-in** that looks normal but flags coercion.
7. **H8 — lock the fuse.** Drop/guard `DMS_*` overrides outside demo mode; treat
   threshold shortening as a privileged change.
8. **C1 / C3 — harden the timer.** Make `watch` resolve config/state from an
   explicit, absolute path (env or flag), not `cwd`; add a second independent leg
   + heartbeat-monitor the watcher itself.
9. **D5 — don't co-locate shares.** `timelock-arm` should write beneficiary
   shares to a separate, clearly-"move me off-box" location (or stream them out),
   and refuse to leave all K pieces in one directory silently.
10. **B5 — make the brake reliable.** Treat webhook non-2xx as failure, retry,
    confirm delivery; require a beneficiary-controlled external channel.

**P2 — long-horizon & platform**

11. **D2** drop the public app tag; **D3/A5** document the permanent-disclosure
    trade and consider a PQ-hybrid before any permanent public storage; **D4**
    reproducible signed builds.
12. **§7** redraw the trust boundary with the platform operator before any
    multi-tenant build; per-owner authenticated state + tenant isolation are
    prerequisites, not features.

---

## 11. Assumptions & accepted risks

- **Assumed:** the offline beneficiary key/shares are competently stored and the
  beneficiary is reachable through a channel they control — human-process risks
  outside the code (✓ docs acknowledge).
- **Accepted for the POC:** file storage, dry-run Arweave, single host. Fine for
  a proof of concept; **not** for protecting anything that matters until P0 is
  done — and `quickstart`'s on-disk beneficiary key (H2) should be fixed before
  it is offered as the easy path.
- **Out of scope here:** formal review of `age`/`tlock`/BLS (delegated upstream);
  the GF(2⁸) Shamir is reviewed for *operational* misuse only, not re-proven.

---

## 12. Re-run triggers (what invalidates this model)

This was written against a tree that changed *during* review. Re-run when any of:
**(a)** `quickstart`/`init` key handling changes (H1/H2); **(b)** the timelock
leg becomes coupled to check-in (H7); **(c)** the real Arweave publisher is wired
(A5, B3, D2, D5 go live); **(d)** any multi-tenant / hosted substrate lands (§7);
**(e)** liveness state gains integrity protection (H4). Each redraws the boundary
in §4.

---

*Method: asset/boundary enumeration → adversary catalogue → per-component threat
walk against the two cardinal failure modes → likelihood × reversibility rating
→ roadmap. Findings carry `file:line` refs to the tree at HEAD on 2026-06-03.*
