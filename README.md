# deadman-10

A small, durable **dead-man switch**: if you stop checking in, your encrypted
file or folder is released to a beneficiary who can open it — and, in durable
mode, it can release itself with **no server and no operator at all**.

One static Go binary. The switch only ever holds **ciphertext** it cannot read.

```
  while you check in ............ nothing happens
  you go quiet ................... WARN, escalating reminders
  you stay quiet ................ FIRE: the encrypted vault is released
  beneficiary (and only them) ... decrypts it
```

## Why it's unusual

A normal service is kept alive by someone who pays for and fixes it. A dead-man
switch is the opposite — **the operator eventually becomes permanently unable to
operate it**. So the design separates two concerns:

- **Confidentiality** — the vault is encrypted to the beneficiary's key, and the
  host keeps only *public* keys: the private keys are printed once at setup for
  you to store offline. So compromising the host leaks **nothing readable** — it
  holds ciphertext only. (Trade-off: keep the beneficiary key, or your own offline
  copy of it, if you want to recover the vault yourself while alive.)
- **Integrity** — the vault is signed at seal time with an offline owner key, so
  the beneficiary can verify it really is yours and reject a forged substitute.
- **Liveness** — a check-in timer decides *when* to release. In durable mode the
  "timer" is the global [drand](https://drand.love) beacon, so the release needs
  no host of yours to be alive.

See [`HOSTING.md`](HOSTING.md) (where to run it) and [`TIMELOCK.md`](TIMELOCK.md)
(the cryptography) for the full design.

## Install

```bash
go build -o dms ./cmd/dms      # single binary, no runtime deps
```

## Quickstart (simple mode — host-run)

```bash
dms init                       # generate owner + beneficiary keys, arm the switch
                               # add --dev to keep the beneficiary key locally for testing
dms seal ~/secrets/            # encrypt a file OR folder -> vault.age (ciphertext)
dms checkin                    # proof of life (resets the timer)
dms status                     # stage + time until warn/fire
dms watch                      # one timer tick (run on a schedule)
dms verify --out ./recovered   # prove recovery works
```

Run `dms watch` on a schedule (cron / launchd / a cheap always-on host). Set
`"notifier": "webhook"` + a Slack webhook URL in `config.json` for delivery with
no UI present.

### See a full warn→fire cycle in seconds

Thresholds are in minutes and overridable for demos — but only with an explicit
`--demo`, so a stray env var can never silently shorten the fuse in production:

```bash
DMS_WARN_AFTER_MINUTES=0 DMS_FIRE_AFTER_MINUTES=999999 dms watch --demo   # WARN
DMS_WARN_AFTER_MINUTES=0 DMS_FIRE_AFTER_MINUTES=0      dms watch --demo   # FIRE
dms verify --out ./recovered                                # beneficiary opens it
dms checkin                                                 # re-arm
```

## Durable mode (no operator) — the interesting part

This is the construction from [`TIMELOCK.md`](TIMELOCK.md): the vault key is split
**K-of-N** with Shamir's Secret Sharing, and **exactly one share** is timelock-
encrypted to a future drand round. The beneficiary holds the other K−1 offline.

```bash
dms timelock-arm ~/secrets/ --unlock-seconds 31536000   # ~1 year backstop
#  kept on this host (each is safe alone):
#    vault.age                   the ciphertext (public-safe)
#    share-timelocked.age        opens itself at the drand round (MUTABLE storage only)
#    RECOVERY-CARD.txt           printable instructions for the beneficiary
#  written to MOVE-OFFBOX-then-delete/ — move off this host NOW, then delete:
#    share-beneficiary-1.txt     give to the beneficiary, store OFFLINE
#    share-raw-owner.txt         owner-only; feeds `timelock-rearm`

# while you're alive, push the deadline out on each check-in — the backstop
# tracks your liveness, and the beneficiary's shares stay valid:
dms timelock-rearm --raw-share /your/offline/share-raw-owner.txt

# once the unlock round is reached:
dms timelock-recover --shares-dir <their-shares> --out ./recovered
```

The host keeps only the timelocked share — never a reconstructable K-of-N set —
and the raw share lives offline with you, supplied only at re-arm time.

**Why a public timelock doesn't leak your secrets:** when the timelocked share
becomes world-readable at the unlock time, it is *one* Shamir share — which
reveals **nothing** on its own. Only someone who *also* holds the beneficiary's
K−1 shares can reconstruct the key. (This is proven by the
`TestTimelockedShareAloneRevealsNothing` test, and the whole arm→recover cycle is
proven against the **live drand network** in `TestCLITimelockArmRecover`.)

This means the release can survive your death, the host's death, and the bill
lapsing — while never broadcasting your secrets to the world.

## The recovery card

The most common reason a dead-man switch fails in practice is that the
beneficiary doesn't know what to do. `dms timelock-arm` writes a
`RECOVERY-CARD.txt` (and `dms recovery-card` prints one anytime) spelling out what
they hold, where the data is, the exact command to run, and the warning that
**losing their shares makes the vault unrecoverable**. Print it. Test it with the
actual beneficiary.

## End to end: who holds what, and two worked setups

Every setup is three parties and a strict custody split. If the host is ever
compromised, the attacker gets ciphertext and public keys — nothing readable,
and nothing that lets them forge a vault in your name.

| party | holds | must never hold |
|---|---|---|
| **the host** (Pi / VPS) | `vault.age` + `vault.age.sig`, public keys, timer state, `share-timelocked.age` | any private key; a full K-of-N share set |
| **you** (owner) | owner signing key, check-in key, `share-raw-owner.txt` — all offline | — |
| **beneficiary** | printed recovery card + beneficiary key (simple) or their K−1 shares (durable) | — |

### Example 1 — the family handover (simple mode)

**Who:** Alex (owner) and Sam (spouse, beneficiary). A Raspberry Pi or $5 VPS.
**What:** `~/handover/` — password-manager emergency kit, account inventory, a letter.

```bash
# 1. on the host, one command sets up everything:
mkdir ~/switch && cd ~/switch
dms quickstart --owner Alex --path ~/handover/ --beneficiary Sam
```

Two private keys print **once and are not kept on the host**: the beneficiary
key goes to Sam (printed, stored with the recovery card), the owner signing key
goes in Alex's safe. Then wire up the routine:

```bash
# 2. schedule the watcher — always an absolute --dir, so cron can't
#    silently run in the wrong directory (it fails loud, by design):
# crontab: */30 * * * * /usr/local/bin/dms --dir /home/alex/switch watch

# 3. notifications with no UI present — in config.json:
#      "notifier": "webhook", "webhook_url": "https://hooks.slack.com/..."
dms notify-test

# 4. proof of life: once a week, from Alex's laptop
ssh pi 'dms --dir /home/alex/switch checkin'
```

Updating the vault later means re-sealing with the offline signing key —
`dms seal ~/handover/ --owner-sign-key <file>` — it never lives on the host.

**What firing looks like:** Alex goes quiet → day 7 the webhook starts nagging
(plenty of time to abort with a single `checkin`) → day 21 the vault is released
to the outbox and the webhook announces where. Sam follows the card: `dms verify`
checks the seal-time signature against Alex's public signing key, then decrypts
with Sam's own key. Run one `--demo` fire-drill with Sam *before* you trust it.

### Example 2 — the no-operator estate backstop (durable mode)

**Who:** you and a sibling. No infrastructure that must outlive you.
**What:** `~/estate/` — will, deeds, final instructions.

```bash
dms timelock-arm ~/estate/ --unlock-seconds 15552000    # ~6 months
```

Then distribute, which is the whole job:

- `share-beneficiary-1.txt` → print two copies, sibling keeps them in two places
- `share-raw-owner.txt` → your offline USB, then **delete `MOVE-OFFBOX-then-delete/`**
- `RECOVERY-CARD.txt` → printed, stored with the will
- `vault.age` → anywhere durable, it's public-safe (cloud drive, even Arweave)
- `share-timelocked.age` → durable but **mutable** storage the sibling can reach
  (a shared cloud folder — never Arweave, because re-arming must replace it)

While you're alive, push the deadline out (e.g. monthly, from your own machine —
the raw share never touches a host; without `--unlock-seconds` the deadline
resets to the ~1-year default):

```bash
dms timelock-rearm --raw-share /Volumes/usb/share-raw-owner.txt --unlock-seconds 15552000
```

If you stop, the drand round arrives and the timelocked share simply becomes
readable — no server of yours involved. The sibling follows the card:

```bash
dms timelock-recover --shares-dir ~/from-the-envelope --out ./recovered
```

### Use both legs

The pulse (warn in days, fire in weeks) reacts fast while the host lives; the
timelock (months) survives the host, the operator, and the unpaid bill. Arm both
over the same folder and make re-arming part of your check-in habit. Two
timescales, each covering the other's failure mode — see
[`HOSTING.md`](HOSTING.md) for host options and check-in patterns.

## Commands

```
quickstart [--owner N --path P --beneficiary B --yes]  guided one-step setup
init [--dev] [--force] [--auth-checkin]   generate keys, arm the switch
seal <path> [--owner-sign-key F]  encrypt + sign a file or folder into the vault
checkin [--checkin-key F]     record proof of life (signed if --auth-checkin)
status [--json]               stage and deadlines
watch [--json]                one timer tick: warn or fire if due
fire --force                  manually trigger the fire path (testing)
verify [--id PATH] [--out D]  decrypt the vault to prove recovery
timelock-arm <path> [--unlock-seconds N] [--shares-out D]  durable arming
timelock-rearm --raw-share F [--unlock-seconds N]   push the deadline forward
timelock-recover [--shares-dir D] [--out DIR]       durable recovery
recovery-card                 print beneficiary instructions
notify-test                   send a test notification
```

Global flags: `--dir <home>` (or `$DMS_HOME`) selects the switch directory —
give schedulers an absolute path; `--demo` is the only way the
`DMS_*_MINUTES` compressed-timer overrides take effect.

## Architecture

```
cmd/dms/                 the CLI
internal/vault           age encrypt/decrypt of a file or folder (tar+gzip)
internal/shamir          self-contained GF(256) K-of-N secret sharing
internal/timelock        drand timelock wrapper (seal/open one share)
internal/custody         the share-timelock construction (Arm/Recover)
internal/engine          the check-in timer (stage, warn, fire-once, re-arm)
internal/release         Publisher + Notifier interfaces; file/dry-run/webhook
internal/keys            age keypair generation
internal/config          settings (thresholds, custody, storage, notifier)
internal/recoverycard    the beneficiary recovery instructions
```

Clean interfaces throughout: swapping the host, the storage backend, or the
notifier never touches the cryptography.

## Status & limitations

- ✅ Simple mode and durable (share-timelock) mode both run, end-to-end, with the
  durable path verified against the live drand beacon.
- ✅ **Arweave** permanent storage is wired (a stdlib-only uploader, verified
  against an arlocal devnet). `dry_run=true` stays the default; a real upload
  requires `dry_run=false` *and* a funded JWK wallet, and refuses otherwise.
  Publish only the vault ciphertext — never the timelocked share (see
  [`TIMELOCK.md`](TIMELOCK.md) §9 on permanence trade-offs).
- ⚠️ **Test your setup.** A dead-man switch you never fire-drill is Schrödinger's
  backup. Run `dms fire --force` / `timelock-recover` and confirm the beneficiary
  path actually works.
- ⚠️ **Firing is irreversible disclosure.** The WARN window is your last chance to
  stop it; tune the thresholds in weeks.
- ⚠️ **Quantum:** both age (X25519) and drand (BLS) are classically secure but
  quantum-breakable on a multi-decade horizon. Keep the inner vault re-encryptable.

## Testing

```bash
go test ./...                                   # fast unit + CLI suite
go test -tags=integration ./internal/timelock/  # live drand round-trip
DMS_INTEGRATION=1 go test ./cmd/dms/            # live arm→recover through the binary
```

## License

MIT — see [LICENSE](LICENSE).
