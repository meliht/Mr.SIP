← [Back to README](../README.md)

# Installation

## Requirements

- Python 3.9+ — check what you have first: `python3 --version`
- `pip`

## Linux

```bash
git clone <repo-url> && cd Mr.SIP

# Recommended: use a virtual environment, so Mr.SIP's dependencies don't
# mix with (or conflict with) other Python projects on your system.
python3 -m venv .venv
source .venv/bin/activate      # your shell prompt should now show (.venv)

pip install -r requirements.txt

python3 mr.sip.py --help
```

Scapy (and `netifaces`/`tqdm`) install from `requirements.txt` via pip — there's no separate system `scapy` package to install. Mr.SIP's raw-packet sends use a Linux raw socket directly, so `libpcap` isn't required for the tool itself (only `ngrep`, if you use it for [traffic inspection](usage-guide.md#watching-live-sip-traffic-with-ngrep), needs it).

Every time you come back to a new terminal session, re-activate the virtual environment before running Mr.SIP: `source .venv/bin/activate` from the repo directory. If you skip this, `python3 mr.sip.py ...` will use your system Python instead, and may fail with `ModuleNotFoundError` for `scapy`/`netifaces`/`tqdm` even though you installed them earlier.

If `pip install -r requirements.txt` fails while building a dependency from source, you're usually missing system build tools — `apt-get install build-essential python3-dev` covers most cases.

Network interfaces are typically named `eth0`, `enpXsY`, or similar. See [Choosing the right network interface](usage-guide.md#choosing-the-right-network-interface---if) if you need to target a specific one.

## macOS

```bash
git clone <repo-url> && cd Mr.SIP

python3 -m venv .venv
source .venv/bin/activate      # your shell prompt should now show (.venv)

pip install -r requirements.txt

python3 mr.sip.py --help
```

Same reminder as above: activate `.venv` again (`source .venv/bin/activate`) every time you return to this repo in a new terminal — otherwise the commands below will silently run against your system Python instead.

No extra system package is needed beyond `requirements.txt`. Network interfaces use different names than Linux (`en0` for the primary Wi-Fi/Ethernet adapter, `en5`/`utun*` for others) — see [Choosing the right network interface](usage-guide.md#choosing-the-right-network-interface---if).

## Root privileges

Root is required only for SIP-DAS's default mode (raw packets, IP spoofing):

```bash
sudo python3 mr.sip.py --das --mt=invite -c 10 --tn=<target_IP> -r
```

(`-c 10` caps this at 10 packets — without a `-c`, SIP-DAS floods by default. Always start with a small count.)

**If you're using a virtual environment, `sudo` needs to see it too** — `sudo` runs with its own environment by default, not your shell's active `.venv`. Either use the venv's own Python binary explicitly:

```bash
sudo .venv/bin/python3 mr.sip.py --das --mt=invite -c 10 --tn=<target_IP> -r
```

or `sudo -E` to preserve your environment (`sudo -E python3 mr.sip.py ...`). If you forget this, you'll get a `ModuleNotFoundError` for a package you're sure you already installed — that's the tell.

Everything else — SIP-NES, SIP-ENUM, and SIP-DAS with `-l`/`--lib` (plain OS sockets, no spoofing) — runs unprivileged:

```bash
python3 mr.sip.py --das --mt=invite -c 10 --tn=<target_IP> -l
```

Running a command that needs root without `sudo` fails immediately with a clear error, before anything is sent.

## Docker

Mr.SIP itself does not run in Docker — it's a local Python CLI tool. Docker is only used to stand up a disposable **test target** to run Mr.SIP against; see [Lab Guide](lab-guide.md) for setup. If you don't already have Docker, install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (macOS) or your distro's `docker`/`docker.io` package (Linux). Any recent version works — UDP port publishing (`-p <port>:<port>/udp`) is the only requirement.

## Version history

See [CHANGELOG.md](../CHANGELOG.md) for what changed between versions.
