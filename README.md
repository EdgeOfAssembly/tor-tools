# tor_control + tor_top — Portable modern C++23 Tor tools

Two simple, dependency-light, modern C++23 command-line programs for advanced Tor users:

- **tor_control**: Full-featured controller for Tor circuits / node selection. Equivalent power to editing `/etc/tor/torrc` + `man tor`, plus live control port commands. Maximum flexibility (fastest nodes only, specific countries, specific fingerprints, strict mode, custom circuit building, etc.).
- **tor_top**: A `top`-like live viewer (plain ANSI escapes only, no ncurses) that shows the currently fastest Tor relays, refreshed periodically.

**Note on tor_top data sources** (important for understanding displayed speeds):
- Prefers Onionoo (https://onionoo.torproject.org) `observed_bandwidth` — the relay's self-reported observed speed (what most public "fastest relay" lists use; matches the original tor_top behavior).
- Falls back to local Tor consensus (`w Bandwidth=` from cached-microdesc-consensus) + `/usr/share/tor/geoip` for country codes. The consensus value is the network-measured weight that Tor actually uses for circuit selection.
- Both are correct but measure different things. Onionoo values tend to reflect advertised/observed capacity; consensus values are what the bandwidth authorities measured. Numbers for the same relay can differ significantly (and change over time). See the code or run with `--help` for details.
- A progress bar (from progress_bar.h) is shown during the potentially slow fetch phase before the TUI appears, so the program never looks hung.

## Design goals (why these exist)
- Maximum flexibility for power users who want to pin or bias node selection far beyond what Tor does by default.
- Work on **any modern Linux** (Ubuntu + systemd, Debian, Fedora, Arch, Gentoo + OpenRC, etc.).
- Single-file, easy to compile and deploy (`g++ -std=c++23`).

## Building

```bash
g++ -std=c++23 -O2 -Wall -Wextra -o tor_control tor_control.cpp
g++ -std=c++23 -O2 -Wall -Wextra -o tor_top     tor_top.cpp
```

Or simply:

```bash
make
```

## Quick portable usage examples

### Authentication (recommended for normal users)

```bash
# One-time setup (run as the tor user or root)
tor --hash-password "MySecretPass123" >> /etc/tor/torrc
# Then restart tor

# Use the program
tor_control --control-password "MySecretPass123" status
# or
export TOR_CONTROL_PASSWORD="MySecretPass123"
tor_control list-nodes --top 30 --exit --country us,de --min-bw 10000
```

Alternative (if you make the control cookie readable by your user):

```bash
sudo usermod -aG tor yourusername   # or debian-tor on Debian/Ubuntu
sudo chmod g+r /var/lib/tor/data/control_auth_cookie   # or the correct data dir
# then tor_control will auto-use the cookie (no password needed)
```

### tor_control — node selection & torrc management

```bash
# See current fastest exits in Germany above 5 MB/s
tor_control list-nodes --exit --country de --min-bw 5000 --top 20

# Generate a strict torrc that only uses fast US/CA exits
tor_control generate-torrc \
    --exit --country us,ca \
    --min-bw 8000 \
    --strict \
    --top 200 > /tmp/fast-us-ca.torrc

# Apply it + restart (uses your normal sudo)
tor_control apply --torrc /tmp/fast-us-ca.torrc --restart

# On Gentoo/OpenRC instead of systemd:
tor_control apply --torrc /tmp/fast-us-ca.torrc --restart-cmd "/etc/init.d/tor restart"

# Custom Tor install
tor_control --data-dir /opt/tor/var/lib/tor --torrc /opt/tor/etc/tor/torrc list-nodes
```

Environment variable for restart (no CLI flag needed):

```bash
export TOR_RESTART_CMD="systemctl restart tor"
tor_control apply --torrc my.torrc --restart
```

### tor_top — live fastest relays (ANSI TUI)

`tor_top` targets standard 80x24 terminals (LXTerm etc.). It uses an alternate screen buffer so the view stays clean in place — scrolling your terminal does not show duplicate/old frames of the TUI. The header is always kept visible at the top; the number of data rows is capped to fit the rest of the terminal.

A progress indicator is shown on the normal terminal *during data fetch* (Onionoo or local consensus) before switching to the full TUI. This makes long fetches obvious and prevents the "is it hung?" feeling.

```bash
tor_top                  # default: top 30, refresh every 15s
tor_top --top 50 --interval 10
tor_top --top 20 --interval 5   # faster updates on small terminals
```

The program will show real country codes (CC) when possible (via Onionoo or local geoip lookup).

See the man page (`man tor_top`) or run with `--help` for all options.

**Data sources note**: See the top of this README for the important explanation of Onionoo vs. local consensus bandwidth values. The program prefers the "classic" high observed numbers from Onionoo when available.

## Important portability notes

- `tor_control` defaults to `systemctl restart tor` (most common on modern distros with systemd). It auto-detects classic `/etc/init.d` layouts if no override is given.
- Use `--restart-cmd "..."` or the `TOR_RESTART_CMD` environment variable for anything else (OpenRC on Gentoo, `service tor restart`, custom scripts, etc.).
- All sensitive paths (`--data-dir`, `--torrc`, `--geoip-file`, `--cookie-file`) are overridable via command line for custom or non-standard Tor installs.
- `sudo` is used only for writing `/etc/tor/torrc` and restarting the daemon. Your normal sudoers configuration (prompt or NOPASSWD) applies. The `--use-sudo-pass` mode (which reads a password file for `sudo -S`) is marked advanced-only and is not used by default.
- `tor_top` is pure local + optional outbound Onionoo. It requires no special privileges for the TUI once data is loaded (the progress phase may use `sudo` for the local consensus/geoip files if they are not readable by your user).

See the man pages (`man tor_control`, `man tor_top`) for full option lists.

## Control port authentication (cross-distro)

The cleanest portable way is a control password (see above).

Cookie auth works if:
- You run with sufficient privileges, or
- The cookie is group-readable and your user is in the tor group.

## Files

- `tor_control.cpp` + binary
- `tor_top.cpp` + binary
- `Makefile`
- `tor_control.1`, `tor_top.1` — man pages (install with your distro's tools or `install -m 644 ... /usr/local/share/man/man1/`)
- `progress_bar.h` — small ANSI progress bar helper (used by tor_top during data fetch)
- `README.md`,  — this documentation

## Documentation

- Run `man tor_control` and `man tor_top` after installing the .1 files.

## License / spirit

Do whatever you want. These are small, auditable tools meant to give you real power over Tor path selection without dragging in Python (stem) or heavy dependencies.

Enjoy controlling your Tor chains exactly the way you want, on whatever Linux you happen to be running.
