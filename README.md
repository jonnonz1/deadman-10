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

Thresholds are in minutes and overridable for demos:

```bash
DMS_WARN_AFTER_MINUTES=0 DMS_FIRE_AFTER_MINUTES=999999 dms watch   # WARN
DMS_WARN_AFTER_MINUTES=0 DMS_FIRE_AFTER_MINUTES=0      dms watch   # FIRE
dms verify --out ./recovered                                        # beneficiary opens it
dms checkin                                                         # re-arm
```

## Durable mode (no operator) — the interesting part

This is the construction from [`TIMELOCK.md`](TIMELOCK.md): the vault key is split
**K-of-N** with Shamir's Secret Sharing, and **exactly one share** is timelock-
encrypted to a future drand round. The beneficiary holds the other K−1 offline.

```bash
dms timelock-arm ~/secrets/ --unlock-seconds 31536000   # ~1 year backstop
#  -> vault.age                  the ciphertext (publish anywhere; public-safe)
#  -> share-timelocked.age       opens itself at the drand round (public-safe)
#  -> share-beneficiary-1.txt    give to the beneficiary, store OFFLINE
#  -> RECOVERY-CARD.txt          printable instructions for the beneficiary

# later, once the unlock round is reached:
dms timelock-recover --out ./recovered
```

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

## Commands

```
init [--dev] [--force]        generate keys, arm the switch
seal <path>                   encrypt a file or folder into the vault
checkin                       record proof of life
status [--json]               stage and deadlines
watch [--json]                one timer tick: warn or fire if due
fire --force                  manually trigger the fire path (testing)
verify [--id PATH] [--out D]  decrypt the vault to prove recovery
timelock-arm <path> [--unlock-seconds N]   durable no-operator arming
timelock-recover [--out DIR]               durable recovery
recovery-card                 print beneficiary instructions
notify-test                   send a test notification
```

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
- ⏳ **Arweave** permanent storage is interfaced but the real uploader isn't wired
  yet — `storage=arweave` requires `dry_run=true` and otherwise refuses (rather
  than silently failing to deliver). Released ciphertext currently goes to a local
  outbox or wherever you publish the files.
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
