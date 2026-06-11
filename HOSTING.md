# deadman-10 — Hosting & Durability Spec

How the switch *actually runs*, where, and how it survives the two deaths that matter:
**yours** and **the host's**. This is a decision document, not an implementation. It
specs the home box, a VPS, serverless, and the decentralised "no-operator" options,
then recommends a layered hybrid.

---

## 1. The one property that makes this hard

A normal service is maintained by someone who stays alive to pay for and fix it. A
dead-man switch is the opposite: **the operator eventually becomes permanently unable
to operate it.** Every hosting decision has to be read through that lens.

Because we encrypt the vault to the beneficiary's key (see `README.md`), the host is:

- **Untrusted for secrecy** — it only ever holds *ciphertext*. A full host compromise
  leaks nothing readable. Good, by design.
- **Trusted for liveness** — it runs the *timer*. This is the entire hosting problem.

So the question is never "find a reliable box." It is:

> **How does the timer survive both my death and the host's death — and fail toward
> firing, loudly, when a leg dies?**

A box you control fails **silently**: it just stops, and nobody notices the switch is
dead until it's needed and isn't there. That silent-death mode is the thing the whole
design fights.

---

## 2. Every hosting choice must answer three sub-questions

| # | Sub-problem | Why it bites |
|---|-------------|--------------|
| **A. Compute** | Where does the `watch` loop run, on a schedule that survives reboots? | If it stops, the switch never fires. |
| **B. State** | Where does `last_checkin` / stage live? | With >1 watcher you get **split-brain**: one leg fires, one doesn't. |
| **C. Storage + egress** | Where does the ciphertext live, and through what channel is it delivered? | The channel must outlive *you* — your own accounts freeze at death. |

And four cross-cutting killers that recur in *every* option below:

1. **The bill** — a card expires after you die → suspension in 30–90 days → the switch
   dies exactly when needed.
2. **The delivery channel** — a Slack-to-self DM or your own Gmail is frozen the moment
   your accounts close. Fire has to land somewhere the *beneficiary* controls.
3. **Silent failure** — a dead switch nobody notices is worthless. Need heartbeat
   monitoring of the watcher itself.
4. **False fire** — premature, irreversible disclosure. The WARN window + escalation
   exist to prevent it; tune it in weeks.

### The state question is the subtle one

The moment there is more than one watcher, they must agree on whether you checked in:

- **Shared state store** all legs read (object store / synced file / the NAS). Moves the
  single point of failure from *compute* (fragile) to *durable storage* (cheap,
  replicable). **Preferred.**
- **Independent legs + quorum.** Any rule has a failure mode: *any-leg-fires* → many
  false fires; *all-legs-agree* → one stuck leg blocks firing forever.
- **drand timelock** sidesteps state entirely: the "state" is *which future timestamp
  the vault is currently encrypted to*, and that lives inside the replicated blob (§5).

---

## 3. Option A — Home box (your Synology / LDR host)  ·  Tier 0

**How the switch actually works**

- A Docker container or `cron`/`systemd` timer on the NAS runs `./dms watch` daily.
- State (`state/last_checkin`, stage) lives on the NAS volume — already RAID-protected
  and mirrored by Synology Drive, so storage is durable for free.
- The **Mac is a second leg** reading the same state via the synced folder, so a home
  outage doesn't blind you.
- Check-in from anywhere: a small handler reachable over **Tailscale**, or the
  email-poll pattern (a scheduled job greps Gmail for a `DMS CHECKIN` sentinel and runs
  `dms checkin`). Phone-friendly, no ports opened.
- Notifier: Slack Incoming Webhook (`"notifier": "webhook"`), so WARN/FIRE post without
  a Claude session or a Mac UI.

| ✅ Strengths | ❌ Weaknesses |
|---|---|
| Free; you own it; runs **today** | Dies with home power / internet |
| Data never leaves the house | **Does not survive your death** — nobody pays the power bill or replaces failed disks forever |
| Perfect for the *check-in UX + nagging* half | Single location; hardware ages out in years |
| RAID + Drive sync = durable state for free | Delivery channel still frozen at death |

**Verdict:** the right home for the **convenience/monitoring layer** and a genuine
near-term deployment. Not a standalone durability guarantee. Pair it with §5.

---

## 4. Option B — VPS  ·  Tier 1

**How the switch actually works**

- A cheap always-on Linux VM runs the same `./dms watch` via a `systemd` timer.
- State in SQLite/flat file, **replicated to object storage** (so the VM is disposable).
- Check-in via a tiny HTTPS endpoint (one route) or the email-poll pattern.
- Notifier: webhook **+ external email to the beneficiary's own address**.
- Provider + geography independent from home → removes the "one location" risk.

**The bill problem (the real VPS killer).** Your card expires after death → suspension →
the switch dies right when it's needed. Mitigations, best first:

1. **Make the VPS *not* load-bearing for the actual fire** — back it with the drand
   timelock (§5). Then a dead VPS costs you *nagging*, not the *fire*.
2. **Remove the bill**: Oracle Cloud **Always Free** ARM VM ($0 forever) or prepay an
   annual/budget provider for years.
3. **Fund a dedicated prepaid account** that won't bounce when your main card closes.

**Sub-options to evaluate (confirm current terms/pricing — see §9):**

| Provider class | Bill posture | Watch-outs |
|---|---|---|
| **Oracle Cloud Always Free** (ARM Ampere A1, up to 4 OCPU/24 GB) | $0, no bill to lapse | **Idle-reclaim trap — see below**; single-vendor ToS; 30-day account-dormancy suspension |
| Budget annual VPS (RackNerd ~$13/yr, V.PS ~€10/yr) | Prepay 1–3 yrs upfront | Small providers fold; verify they honour multi-year prepay |
| Multi-year (HostHatch 3-yr deals) | One payment covers years | Still finite; provider longevity risk |
| Hetzner / OVH small instance | Cheap monthly | Still a recurring card |

> **⚠️ The Oracle-free idle-reclaim trap is specific to *this* workload.** Oracle reclaims
> an Always-Free VM if, over 7 days, 95th-percentile **CPU <20% AND network <20% AND
> memory <20%**. A dead-man switch is *by nature* near-idle — a daily `watch` tick uses
> almost nothing — so it fits the reclaim profile **exactly**. It would be silently
> deleted, the worst failure mode. Mitigations: convert the tenancy to **Pay-As-You-Go**
> (still $0 within free limits, but **exempt from idle reclaim**), or run a keep-busy
> job. Either way this is a managed box, not a fire-and-forget one — which is why the
> §5 backstop matters even here.

| ✅ Strengths | ❌ Weaknesses |
|---|---|
| Always-on, off-site, full control | **The bill** (unless Oracle-free / prepaid) |
| Can run the real fire path end-to-end | Provider can vanish or suspend |
| Cheap | Still a *single* host unless you run ≥2 |
| | You patch an OS unattended **for years** — attack surface grows |

**Verdict:** the workhorse for actually *firing* off-site. Its weaknesses (bill, single
host, unattended patching) are exactly what the no-operator backstop in §5 neutralises.

---

## 5. Option D — Decentralised / no-operator  ·  the durability backbone

This is the researched "other options," and it's where the *survives-everything*
guarantee actually comes from. The key move: **separate the convenience layer (a host
that nags you) from the guarantee layer (a fire that needs no host at all).**

### 5.1 drand timelock encryption (`tlock`) — the centrepiece

Encrypt the vault to **"now + T"**. The drand network publishes the decryption key for
round *R* automatically at that future time. **Re-arming = on each check-in, re-encrypt
to a fresh now+T and re-publish the blob.** Stop checking in → at T the blob becomes
**self-decrypting with no server and no human.**

This *inverts* the hosting problem:

- The "timer" is the **global drand beacon**, not your box.
- Your host's only remaining job is **pushing the deadline forward while you're alive**.
- If the host dies, the switch **still fires** — it *fails toward firing* (fail-safe),
  the opposite of a silent dead host.

*Grounded status (verified live 2026-06-01):* drand is run by the **League of Entropy in
production since 2019**; timelock has been **GA on mainnet since March 2023**; the scheme
was **audited by Kudelski**; implementations exist in **Go (`tle`), TypeScript, and
Rust**. The `quicknet` beacon used for timelock is live with **3-second rounds**
(`period: 3`, `genesis_time: 1692803367`, chain hash
`52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`, scheme
`bls-unchained-g1-rfc9380`). So re-arming is a pure calculation, no server state:

```
round_for(T) = floor((T - 1692803367) / 3) + 1     # the round that opens at time T
# CLI equivalent on each check-in (re-lock for, say, 30 days out):
tle --round $(round_for now+30d) -o vault.tlock.age vault.age
```

Caveats: you must re-publish on every check-in, and you depend on drand surviving
(mitigate: it's a multi-org public good; keep a Shamir-trustee fallback path too).

### 5.2 Arweave / permaweb — the answer to the *bill* problem for storage

Arweave uses a **pay-once, store-forever endowment** model: a single upfront payment
funds ~200 years of replication (95% of the fee goes into an endowment that pays miners
over time). **You cannot be late on a bill you have already fully paid.** Put the
*(timelock-encrypted)* blob on Arweave and the **storage leg never dies** regardless of
your death or any company's death.

*Grounded cost (live 2026-06-01):* the network price endpoint returns **~9.38×10⁹ winston
per MiB** at **AR ≈ $2.23**, i.e. **≈ US$0.02 per MiB, one-time, forever**. A real
deadman vault is a few KB → **a fraction of a cent, paid once.** This single fact removes
the recurring-bill killer from the storage leg entirely.

### 5.3 Other no-operator options

| Option | How it fires without you | Bill posture | Maturity / caveat |
|---|---|---|---|
| **IPFS + Filecoin** | Content-addressed retrieval | Pinning/deals **renew** → weaker than Arweave unless prepaid service | Mature, but renewal is an ongoing-bill trap |
| **Threshold network (TACo / Lit Naga)** | Committee releases key shares when your timeout condition is met | Network token economics | Newest/most complex; no single custodian (strong) but depends on the network |
| **Smart-contract switch (cheap L2)** | `release()` callable by anyone after the on-chain timer expires; check-in = a tx that resets it | Gas per check-in | Survives without you; depends on the chain; this is the Inheriti/SSS-on-chain pattern |
| **Google Inactive Account Manager** | Google emails contacts a data export after 3–18 mo inactivity (≤10 contacts) | $0, Google-run | Zero-build backstop; trust + scope limited to Google data, export not login |
| **Commercial (Just In Case, Cipherwill)** | Their infra | Subscription | Outsources trust *and* longevity to a company that may pivot/fail |

---

## 6. Option C — Serverless / managed cron  ·  Tier 1.5 (and the platform substrate)

No VM to patch; the watcher can't "silently die" the way a box does — but it still has a
*bill* and a *vendor*.

| Platform | Compute (watch) | State | Ciphertext | Check-in | Delivery |
|---|---|---|---|---|---|
| **Cloudflare** | Cron Triggers (Worker) | D1 / KV | R2 | Worker HTTP route | Worker → email API |
| **AWS** | EventBridge Scheduler → Lambda | DynamoDB | S3 | API Gateway → Lambda | SES |
| **GitHub Actions** | Scheduled workflow | repo (commits = check-ins) | repo/release | commit/dispatch | Action step |

- **Cloudflare** is the cleanest fit and the natural **multi-tenant substrate** (§8).
  *Grounded limits (live 2026-06-01):* free plan = **100,000 requests/day** (resets
  00:00 UTC); **Cron Triggers max 15 min wall-time** per invocation (plenty to sweep all
  owners); **D1 free up to 10 GB/db**; **R2 has no egress charges** (free fire delivery).
  One scheduled Worker iterates *all* owners' timers.
- **AWS** alternative: EventBridge Scheduler gives **14M free invocations/month
  (permanent)** with native one-time schedules, retries, and a dead-letter queue — a
  robust managed timer if you prefer AWS.
- **GitHub Actions has an ironic failure mode**: scheduled workflows are **disabled
  after ~60 days of repo inactivity** — a dead-man switch that turns *itself* off when
  you stop touching the repo. Avoid for the fire path.
- Shared killers remain: payment failure suspends Cloudflare/AWS too, and **account
  closure on death** is the real risk. Mitigate with the §5 backstop + prepaid
  credits + an **org/entity account** (not personal) for a multi-tenant service.

| ✅ Strengths | ❌ Weaknesses |
|---|---|
| No OS to maintain; no box to silently die | Still a bill; still a vendor |
| Cheap → free at personal scale | Account-closure-on-death risk |
| Scales straight to the platform | Vendor ToS / dormancy |

---

## 7. The synthesis — host is the *pulse*, drand+Arweave is the *insurance*

The unifying idea across all options:

```
  CONVENIENCE / MONITORING LAYER          GUARANTEE LAYER (no operator)
  home box + VPS/serverless run `watch`,  vault is ALSO a drand-timelocked blob
  send WARN nags, give check-in UX,       on Arweave (paid once).
  show status.                            Opens at T even if every host, every
  If these die → you lose NAGGING.        bill, and you are gone. Fail-safe.
                         \                /
                          CUSTODY LAYER (from the trust-model discussion)
                          blob encrypted to beneficiary key(s); Shamir / threshold
                          so no single party can open early.
```

**Durability does not actually depend on which host you pick.** Pick the host tier by
how much convenience/effort you want; the *fire* is guaranteed by the substrate. This is
also the answer to SaaS-longevity: even if the platform (you) dies, every owner's switch
still fires via its own timelock escrow.

---

## 8. The multi-tenant platform (your "many independent owners" choice)

- **Compute:** one Cloudflare Cron Worker iterates every owner's timer (or EventBridge
  + Lambda). Stateless; horizontally trivial.
- **State:** one row per owner — `{owner_id, last_checkin, warn_at, fire_at, status}`.
  **Timestamps only. Never keys, never plaintext.**
- **Ciphertext:** R2/S3 per owner, **and** mirrored as a **per-owner drand-timelocked
  Arweave blob**, so the platform's death doesn't doom anyone.
- **Check-in:** authenticated HTTPS endpoint + email-reply + optional app.
- **Delivery:** email to the **beneficiary's own** address, with the Arweave tx id as
  the permanent fallback location.
- **Security posture:** the platform stores only ciphertext + timers → a breach leaks
  nothing; the platform dying still lets every switch fire. That is the whole pitch.

---

## 9. Decision matrix

| Option | Survives *your* death | Survives *host* death | Bill-proof | Maint. burden | Cost | Complexity | Fires fail-safe |
|---|---|---|---|---|---|---|---|
| A. Home box | ❌ | ❌ | ❌ | low | $0 | low | ❌ (silent stop) |
| B. VPS (paid) | ⚠️ until bill lapses | ❌ single | ❌ | **high** (years unattended) | $ | low | ❌ |
| B. VPS (Oracle-free) | ⚠️ ToS/dormancy | ❌ single | ✅ | high | $0 | low-med | ❌ |
| C. Serverless | ⚠️ acct closure | ✅ (managed) | ⚠️ credits | **none** | ~$0 | med | ❌ |
| D. drand timelock | ✅ | ✅ | ✅ (with Arweave) | none | one-time | med | **✅** |
| D. Arweave storage | ✅ | ✅ | **✅ pay-once** | none | one-time | low | n/a (storage) |
| D. Threshold net | ✅ | ✅ | ⚠️ tokenomics | none | $ | high | ✅ |
| Google IAM | ✅ | ✅ | ✅ | none | $0 | trivial | ✅ (limited scope) |

**Grounded figures (verified live 2026-06-01) — these were checked against primary
sources, not estimated:**

| Fact | Verified value | Source |
|---|---|---|
| Arweave one-time storage | **≈ $0.02 / MiB** (9.38×10⁹ winston/MiB @ AR $2.23); few-KB vault ≪ 1¢ | `arweave.net/price` + CoinGecko |
| drand quicknet (timelock) | **3 s rounds**, genesis 1692803367, chain `52db9ba7…84e971` | `api.drand.sh/.../info` |
| Cloudflare free | **100k req/day**, cron **15 min** max, D1 **10 GB**, R2 **no egress fee** | CF Workers docs |
| AWS EventBridge Scheduler | **14M invocations/mo free, permanent**; one-time + DLQ | AWS docs |
| Oracle Always Free ARM | **4 OCPU / 24 GB**, but **reclaimed if 7-day CPU&net&mem all <20%** | OCI docs |
| Budget VPS | RackNerd ~$13/yr, V.PS ~€10/yr, HostHatch 3-yr deals | LowEndTalk |

Lopp's "Fifteen men on a dead man's switch" reinforces the §7 conclusion from the
crypto-inheritance world: **no single service is trustworthy enough alone** ("you'd need
hundreds or thousands … to bring the odds of all failing or colluding close to 0"); the
practical answer is **Shamir trustees + tested plaintext instructions + annual refresh**
— i.e. the custody layer, with hosting as replaceable plumbing.

---

## 10. Recommended path for you specifically

You already self-host (LDR box, Synology Drive), so:

1. **Now — home box leg (Tier 0):** Docker `dms watch` on the NAS + Mac second leg,
   Slack-webhook notifier, Tailscale/email check-in. Real, running, gives you the
   nagging + UX. *This is the deploy-it-today step from the earlier hosting question.*
2. **Add — the guarantee (Tier "D"):** wrap the vault as a **drand-timelocked blob on
   Arweave**. One-time cost, no recurring bill, fires even if the home box and you are
   both gone. This is the actual durability, and it makes the host non-load-bearing.
3. **Later — platform (Tier 2):** Cloudflare Cron Worker + per-owner D1/R2 + **per-owner
   Arweave/drand escrow**. Stores only ciphertext + timers; survives the platform's own
   death.

Each layer is swappable behind a clean interface (the four layers in `README.md`):
changing the host never touches custody, check-in, or notify. That keeps the system
simple to reason about and safe to refactor — and it makes the fire **fail-safe** rather
than fail-silent.

### Single-host SPOF (threat model C1) — a deployment rule, not a code fix

One host running `watch` is a single point of failure: if it dies, the bill lapses, or
the scheduler is disabled, the switch **never fires and nobody notices**. There is no
code that fixes this — it is a *deployment* property:

- **Run `watch` on ≥2 independent hosts** (e.g. the NAS + a prepaid VPS), each with an
  absolute `--dir`/`$DMS_HOME` (so C3's cwd footgun can't silently disable one). They
  share state via the synced vault dir, or run as fully independent legs.
- **The drand timelock backstop IS the second leg that needs no host of yours.** Once
  armed (and re-armed on check-in), it fires even if every machine you own is gone — so
  the SPOF of the *convenience* layer stops being the SPOF of the *fire*.
- **Heartbeat-monitor the watcher itself** with something you already trust (a healthcheck
  ping from each `watch` run). A dead-man switch whose watcher silently died is the worst
  failure; don't rely on noticing by accident.

(A built-in "watcher-of-the-watcher" is deliberately *not* implemented — it just moves the
question to "who watches that?". Use the timelock backstop + an external healthcheck.)

---

### Open decisions for you

- **Check-in channel** you actually want (Tailscale handler vs. email-poll vs. app)?
- **Beneficiary delivery channel** that outlives you (their email? a printed Arweave tx
  id + decryption instructions in a will? a trustee)?
- **drand re-arm cadence** (re-publishing on every check-in is the cost of the fail-safe
  backstop — acceptable, or do you want it only as a periodic safety net)?
- **Oracle-free vs. prepaid VPS vs. serverless** for the always-on leg, if you want one
  beyond the home box?

---

## Appendix — the timelock re-arm trade-off (read before choosing drand)

The drand backstop is the strongest durability lever **and** the sharpest design
trade-off, so it deserves an explicit caveat rather than a footnote:

- **What you gain:** the fire needs *no host and no human*. If every box and you are
  gone, the blob self-opens at T. This is the only option here that is truly
  **fail-safe** (fails toward firing).
- **What it costs:** the deadline is **baked into the ciphertext**, so "I'm still alive"
  means **re-encrypting to a fresh now+T and re-publishing the blob on every check-in.**
  Miss the re-publish window (host down for longer than T) and it **fires while you're
  alive** — a false positive that timer-only designs don't have.
- **The tension:** a short T (e.g. 30 days) = tight fail-safe but unforgiving of an
  outage; a long T (e.g. 12 months) = forgiving but slow to fire. There is no setting
  that is both.
- **The resolution (recommended):** run drand as a **periodic safety-net with a long T
  (6–12 mo)**, while the **host-run `watch` + WARN escalation handles the normal,
  short-cycle** liveness. Normal operation fires fast and is recoverable; the timelock
  only ever fires if the *entire host layer* has also been dead for the long T. Two
  independent timescales, each covering the other's failure mode — neither alone has to
  be both fast and forgiving.

This is why §7 frames host vs. substrate as *pulse vs. insurance*: you don't pick one,
you set their timescales so the gap between them is the safety margin.
