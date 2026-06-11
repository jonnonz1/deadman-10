#!/usr/bin/env python3
"""deadman-10 - a simple, swappable dead-man switch (proof of concept).

Four deliberately independent layers, so any one can be upgraded without touching
the others:

  1. Vault    payload encrypted with `age` to recipient public keys. The machine
              running the switch only ever holds CIPHERTEXT, so a compromise of the
              switch (or its host) never reveals the payload.
  2. Liveness a single check-in timestamp the owner refreshes to prove they're alive.
  3. Watch    compares now vs last check-in -> HEALTHY | WARN | FIRE, and acts.
  4. Notify   pluggable delivery: local notification | Slack webhook | stdout.

Custody model: the vault is encrypted to the BENEFICIARY's age public key (and the
owner's, so the owner can always recover). The beneficiary's PRIVATE key lives with
the beneficiary, never on the switch. Firing therefore just delivers the ciphertext;
only the beneficiary can open it. Swapping custody (Shamir shares, drand timelock, a
threshold network) changes only how that key/ciphertext is protected - not the
check-in, watch, or notify machinery.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "config.json")

DEFAULTS = {
    "owner_name": "Owner",
    "warn_after_minutes": 10080,   # 7 days
    "fire_after_minutes": 30240,   # 21 days
    "vault_path": "vault.age",
    "recipients_file": "keys/recipients.txt",
    "keys_dir": "keys",
    "state_dir": "state",
    "outbox_dir": "outbox",
    "notifier": "local",           # local | webhook | stdout
    "webhook_url": "",
}


def load_config():
    """Return config merged over defaults, with env overrides for the demo timers."""
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    for key, env in (("warn_after_minutes", "DMS_WARN_AFTER_MINUTES"),
                     ("fire_after_minutes", "DMS_FIRE_AFTER_MINUTES")):
        if os.environ.get(env):
            cfg[key] = float(os.environ[env])
    return cfg


def path_of(cfg, key):
    """Resolve a config path value relative to BASE unless it is absolute."""
    val = cfg[key]
    return val if os.path.isabs(val) else os.path.join(BASE, val)


def state_file(cfg, name):
    """Return the absolute path to a file inside the state directory."""
    return os.path.join(path_of(cfg, "state_dir"), name)


def now():
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def iso(dt):
    """Format a datetime as a second-precision ISO 8601 string."""
    return dt.replace(microsecond=0).isoformat()


def read_text(path, default=None):
    """Read and strip a text file, returning default if it is missing."""
    try:
        with open(path) as f:
            return f.read().strip()
    except FileNotFoundError:
        return default


def write_text(path, text):
    """Write text to path, creating parent directories as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def run(cmd):
    """Run a subprocess, capturing output and raising with stderr on failure."""
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


def require_age():
    """Exit with guidance if the age toolchain is not installed."""
    if shutil.which("age") is None or shutil.which("age-keygen") is None:
        sys.exit("error: `age` not installed. Run: brew install age")


def last_checkin(cfg):
    """Return the datetime of the last check-in, or None if never checked in."""
    ts = read_text(state_file(cfg, "last_checkin"))
    return datetime.fromisoformat(ts) if ts else None


def minutes_since(dt):
    """Return whole and fractional minutes elapsed since dt."""
    return (now() - dt).total_seconds() / 60.0


def compute_stage(cfg):
    """Return (stage, minutes_since_checkin) where stage is HEALTHY|WARN|FIRE|UNKNOWN."""
    checkin = last_checkin(cfg)
    if checkin is None:
        return ("UNKNOWN", None)
    mins = minutes_since(checkin)
    if mins >= cfg["fire_after_minutes"]:
        return ("FIRE", mins)
    if mins >= cfg["warn_after_minutes"]:
        return ("WARN", mins)
    return ("HEALTHY", mins)


def notify(cfg, level, subject, body):
    """Deliver a notification via the configured method and append it to the log."""
    line = f"{iso(now())} [{level}] {subject} :: {body}"
    log = state_file(cfg, "notifications.log")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    with open(log, "a") as f:
        f.write(line + "\n")

    method = cfg.get("notifier", "local")
    if method == "local" and shutil.which("osascript"):
        script = f'display notification {json.dumps(body)} with title {json.dumps("DMS: " + subject)}'
        subprocess.run(["osascript", "-e", script])
    elif method == "webhook" and cfg.get("webhook_url"):
        payload = json.dumps({"text": f"*{subject}*\n{body}"})
        subprocess.run(["curl", "-s", "-X", "POST", "-H",
                        "Content-type: application/json", "--data", payload,
                        cfg["webhook_url"]])
    print(line)


def bump_nag(cfg):
    """Increment and return the escalating nag counter."""
    f = state_file(cfg, "nags")
    n = int(read_text(f, "0")) + 1
    write_text(f, str(n))
    return n


def do_warn(cfg, mins):
    """Send an escalating warning that the switch is approaching its fire deadline."""
    remaining = cfg["fire_after_minutes"] - mins
    n = bump_nag(cfg)
    notify(cfg, "WARN", f"Dead-man warning #{n}",
           f"No check-in for {mins:.0f} min. Fires in {remaining:.0f} min. "
           f"Run `dms checkin` if you're alive.")


def do_fire(cfg, mins):
    """Release the ciphertext to the outbox and notify; idempotent via a FIRED marker."""
    outbox = path_of(cfg, "outbox_dir")
    os.makedirs(outbox, exist_ok=True)
    vault = path_of(cfg, "vault_path")
    released = os.path.join(outbox, "vault.age")
    if os.path.exists(vault):
        shutil.copy2(vault, released)
    note = (
        f"deadman-10 FIRED at {iso(now())} after {mins:.0f} min without check-in.\n\n"
        f"The encrypted vault is: {released}\n"
        f"Decrypt it with the beneficiary identity that was handed to you at setup:\n\n"
        f"    age -d -i beneficiary.key vault.age > recovered.txt\n"
    )
    write_text(os.path.join(outbox, "FIRED.txt"), note)
    write_text(state_file(cfg, "FIRED"), iso(now()))
    notify(cfg, "FIRE", "Dead-man switch FIRED",
           f"No check-in for {mins:.0f} min. Vault released to {released}. "
           f"Only the beneficiary key can open it.")


def cmd_init(cfg, args):
    """Generate owner + beneficiary keypairs and arm the switch."""
    require_age()
    keys = path_of(cfg, "keys_dir")
    if os.path.exists(os.path.join(keys, "recipients.txt")) and not args.force:
        sys.exit("already initialized (use --force to regenerate keys)")
    vault = path_of(cfg, "vault_path")
    if args.force and os.path.exists(vault):
        sys.exit(
            f"refusing to rotate keys: {vault} exists and is encrypted to the current "
            f"keys. Regenerating them would make it PERMANENTLY unopenable. Move or "
            f"delete the vault (and re-seal afterwards) if you really want new keys.")
    for d in ("keys_dir", "state_dir", "outbox_dir"):
        os.makedirs(path_of(cfg, d), exist_ok=True)

    owner_key = os.path.join(keys, "owner.key")
    run(["age-keygen", "-o", owner_key])
    os.chmod(owner_key, 0o600)
    owner_pub = run(["age-keygen", "-y", owner_key]).stdout.strip()

    ben_key = os.path.join(keys, "beneficiary.key")
    run(["age-keygen", "-o", ben_key])
    os.chmod(ben_key, 0o600)
    ben_pub = run(["age-keygen", "-y", ben_key]).stdout.strip()
    ben_priv = read_text(ben_key)
    if not args.dev:
        os.remove(ben_key)

    write_text(os.path.join(keys, "owner.pub"), owner_pub + "\n")
    write_text(os.path.join(keys, "beneficiary.pub"), ben_pub + "\n")
    write_text(cfg_recipients(cfg), owner_pub + "\n" + ben_pub + "\n")
    write_text(state_file(cfg, "last_checkin"), iso(now()))
    write_text(state_file(cfg, "stage"), "HEALTHY")
    write_text(state_file(cfg, "nags"), "0")
    for marker in ("FIRED",):
        m = state_file(cfg, marker)
        if os.path.exists(m):
            os.remove(m)

    print("deadman-10 initialized.")
    print(f"  owner public key       : {owner_pub}")
    print(f"  beneficiary public key : {ben_pub}")
    print(f"  recipients file        : {cfg_recipients(cfg)}")
    print()
    print("=" * 70)
    print("BENEFICIARY PRIVATE KEY - hand this to your beneficiary and store it")
    print("OFFLINE. The switch keeps only the public key and can never read the")
    print("vault. Without this key the payload is unrecoverable.")
    print("=" * 70)
    print(ben_priv)
    print("=" * 70)
    if args.dev:
        print(f"[dev] beneficiary key also saved to {ben_key} for local testing only.")


def cfg_recipients(cfg):
    """Return the absolute path to the recipients (public keys) file."""
    return path_of(cfg, "recipients_file")


def cmd_seal(cfg, args):
    """Encrypt a plaintext payload into the vault for all configured recipients."""
    require_age()
    rec = cfg_recipients(cfg)
    if not os.path.exists(rec):
        sys.exit("run `dms init` first")
    out = path_of(cfg, "vault_path")
    run(["age", "-R", rec, "-o", out, args.payload])
    print(f"sealed {args.payload} -> {out} ({os.path.getsize(out)} bytes of ciphertext)")


def cmd_checkin(cfg, args):
    """Record proof of life: reset the timer and clear any warning/fired state."""
    write_text(state_file(cfg, "last_checkin"), iso(now()))
    write_text(state_file(cfg, "stage"), "HEALTHY")
    write_text(state_file(cfg, "nags"), "0")
    fired = state_file(cfg, "FIRED")
    if os.path.exists(fired):
        os.remove(fired)
    print(f"checked in at {iso(now())}")
    print(f"  warns after {cfg['warn_after_minutes']:g} min, "
          f"fires after {cfg['fire_after_minutes']:g} min without check-in")


def status_dict(cfg):
    """Return a machine-readable snapshot of the switch state."""
    stage, mins = compute_stage(cfg)
    checkin = last_checkin(cfg)
    return {
        "stage": stage,
        "last_checkin": iso(checkin) if checkin else None,
        "minutes_since_checkin": round(mins, 2) if mins is not None else None,
        "warn_after_minutes": cfg["warn_after_minutes"],
        "fire_after_minutes": cfg["fire_after_minutes"],
        "fired": os.path.exists(state_file(cfg, "FIRED")),
        "notifier": cfg.get("notifier"),
    }


def cmd_status(cfg, args):
    """Print the current stage and time remaining until warn/fire."""
    s = status_dict(cfg)
    if args.json:
        print(json.dumps(s, indent=2))
        return
    print(f"stage          : {s['stage']}")
    print(f"last check-in  : {s['last_checkin']}")
    if s["minutes_since_checkin"] is not None:
        to_warn = s["warn_after_minutes"] - s["minutes_since_checkin"]
        to_fire = s["fire_after_minutes"] - s["minutes_since_checkin"]
        print(f"since check-in : {s['minutes_since_checkin']:.1f} min")
        print(f"-> warn in     : {to_warn:.1f} min")
        print(f"-> fire in     : {to_fire:.1f} min")
    print(f"fired          : {s['fired']}")


def cmd_watch(cfg, args):
    """One tick of the timer: evaluate the stage and warn or fire as needed."""
    stage, mins = compute_stage(cfg)
    fired = os.path.exists(state_file(cfg, "FIRED"))
    action = "none"
    if stage == "FIRE" and not fired:
        do_fire(cfg, mins)
        action = "fired"
    elif stage == "WARN":
        do_warn(cfg, mins)
        action = "warned"
    write_text(state_file(cfg, "stage"), stage)

    result = status_dict(cfg)
    result["action"] = action
    if args.json:
        print(json.dumps(result))
    else:
        ms = result["minutes_since_checkin"]
        print(f"[watch] stage={stage} since={ms}min action={action}")


def cmd_fire(cfg, args):
    """Manually trigger the fire path (for testing the delivery end-to-end)."""
    if not args.force:
        sys.exit("refusing to fire without --force")
    _, mins = compute_stage(cfg)
    do_fire(cfg, mins if mins is not None else 0)
    print("fired (forced).")


def cmd_verify(cfg, args):
    """Prove the round-trip: decrypt the vault with a beneficiary identity."""
    require_age()
    ident = args.identity or os.path.join(path_of(cfg, "keys_dir"), "beneficiary.key")
    if not os.path.exists(ident):
        sys.exit(f"identity not found: {ident} (pass --identity, or `init --dev`)")
    res = run(["age", "-d", "-i", ident, path_of(cfg, "vault_path")])
    print("--- decrypted payload ---")
    print(res.stdout)
    print("--- end ---")


def cmd_notify_test(cfg, args):
    """Send a test notification through the configured notifier."""
    notify(cfg, "TEST", "deadman-10 test", "If you can read this, notifications work.")


def build_parser():
    """Construct the argparse command-line interface."""
    parser = argparse.ArgumentParser(prog="dms", description="deadman-10 dead-man switch (POC)")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="generate keys and arm the switch")
    init.add_argument("--dev", action="store_true",
                      help="also keep the beneficiary key locally for testing")
    init.add_argument("--force", action="store_true", help="overwrite existing keys")
    init.set_defaults(func=cmd_init)

    seal = sub.add_parser("seal", help="encrypt a payload file into the vault")
    seal.add_argument("payload", help="path to the plaintext payload to seal")
    seal.set_defaults(func=cmd_seal)

    checkin = sub.add_parser("checkin", help="record proof of life")
    checkin.set_defaults(func=cmd_checkin)

    status = sub.add_parser("status", help="show current stage and deadlines")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    watch = sub.add_parser("watch", help="one timer tick: warn or fire if due")
    watch.add_argument("--json", action="store_true")
    watch.set_defaults(func=cmd_watch)

    fire = sub.add_parser("fire", help="manually trigger the fire path")
    fire.add_argument("--force", action="store_true")
    fire.set_defaults(func=cmd_fire)

    verify = sub.add_parser("verify", help="decrypt the vault to prove recovery works")
    verify.add_argument("--identity", help="path to a beneficiary/owner age identity")
    verify.set_defaults(func=cmd_verify)

    nt = sub.add_parser("notify-test", help="send a test notification")
    nt.set_defaults(func=cmd_notify_test)
    return parser


def main():
    """Parse arguments and dispatch to the selected command."""
    cfg = load_config()
    args = build_parser().parse_args()
    args.func(cfg, args)


if __name__ == "__main__":
    main()
