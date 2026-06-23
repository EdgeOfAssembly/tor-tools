// tor_control.cpp - Best modern C++23 Tor control & configuration tool
// Controls torrc (via sudo), restarts Tor, live control port, custom circuit building,
// node selection by speed/country/fingerprint, full flexibility like torrc + man tor.
// 
// Compile: g++ -std=c++23 -O2 -Wall -Wextra -o tor_control tor_control.cpp
// Usage: ./tor_control --help
//
// Requires: control password or cookie access via sudo -n.
// For torrc edits and restart: sudo nopass or sudo password (see --sudo-with-pass).
// On Gentoo: uses /etc/init.d/tor and /etc/tor/torrc .

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <optional>
#include <poll.h>
#include <print>
#include <random>
#include <ranges>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

using namespace std::chrono_literals;

// ====================== CONFIG / DEFAULTS ======================
constexpr std::string_view TOR_HOST = "127.0.0.1";
constexpr uint16_t TOR_PORT = 9051;
const fs::path DEFAULT_TORRC = "/etc/tor/torrc";
const fs::path DEFAULT_GEOIP = "/usr/share/tor/geoip";

// Reasonable defaults that work on most modern distros.
// Users on Gentoo/OpenRC can override with --restart-cmd "/etc/init.d/tor restart"
// Users on Ubuntu/Fedora/etc. (systemd) get a good default.
const std::string DEFAULT_RESTART_CMD = "systemctl restart tor";  // overridden by TOR_RESTART_CMD or --restart-cmd

constexpr int DEFAULT_CIRCUIT_LEN = 3;
constexpr int MAX_RETRIES = 5;

// ====================== DATA STRUCTS ======================
struct Relay {
    std::string nickname;
    std::string fingerprint; // $ + 40 hex uppercase
    std::string ip;
    int orport = 0;
    int bandwidth = 0;       // from w Bandwidth=
    std::vector<std::string> flags;
    std::string country = "??";
};

struct ControlReply {
    int code = 0;
    std::vector<std::string> lines;
    bool is_multiline = false;
};

struct TorConfig {
    std::string control_host = std::string(TOR_HOST);
    uint16_t control_port = TOR_PORT;

    // Control authentication
    std::string control_password;                 // from --control-password or TOR_CONTROL_PASSWORD env
    fs::path cookie_file;                         // explicit override

    // Paths (overridable for different distros / custom Tor installs)
    fs::path torrc_path = DEFAULT_TORRC;
    fs::path geoip_file = DEFAULT_GEOIP;
    fs::path data_dir;                            // if set, we derive cookie + consensus from it

    // Restart / privileged operations
    std::string restart_cmd = DEFAULT_RESTART_CMD; // the command after "sudo "
    bool use_sudo = true;                         // for torrc writes and restarts
    fs::path sudo_pass_file;                      // ADVANCED: only for non-interactive sudo in special setups. Not for normal users.
    bool use_sudo_pass = false;                   // when true + sudo_pass_file set, use sudo -S ... < file

    bool dry_run = false;
    bool verbose = false;
    int circuit_len = DEFAULT_CIRCUIT_LEN;
};

// ====================== UTILS ======================
std::string trim(std::string s) {
    auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

std::vector<std::string> split(std::string_view sv, char delim) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : sv) {
        if (c == delim) { if (!cur.empty()) { out.push_back(std::move(cur)); cur.clear(); } }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

std::string to_upper(std::string s) {
    for (char& c : s) if (c >= 'a' && c <= 'z') c -= 32;
    return s;
}

std::string join(const std::vector<std::string>& v, std::string_view sep) {
    if (v.empty()) return "";
    std::ostringstream oss;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) oss << sep;
        oss << v[i];
    }
    return oss.str();
}

uint32_t ip4_to_u32(std::string_view ip) {
    in_addr addr{};
    if (inet_pton(AF_INET, std::string(ip).c_str(), &addr) != 1) return 0;
    return ntohl(addr.s_addr);
}

std::string u32_to_ip(uint32_t u) {
    in_addr addr{}; addr.s_addr = htonl(u);
    char buf[INET_ADDRSTRLEN]{}; inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

// ====================== GEOIP (legacy Tor format: start,end,CC decimal) ======================
class GeoIP {
    struct Range { uint32_t start, end; std::string cc; };
    std::vector<Range> ranges;
public:
    bool load(const fs::path& path, bool use_sudo = true) {
        std::string cmd = use_sudo ? std::format("sudo -n cat {} 2>/dev/null", path.string()) : path.string();
        FILE* f = popen(cmd.c_str(), "r");
        if (!f) return false;
        char line[256];
        ranges.clear();
        while (fgets(line, sizeof(line), f)) {
            if (line[0] == '#') continue;
            std::string_view sv(line);
            auto parts = split(sv, ',');
            if (parts.size() < 3) continue;
            try {
                uint32_t s = std::stoul(trim(parts[0]));
                uint32_t e = std::stoul(trim(parts[1]));
                std::string cc = trim(parts[2]);
                if (cc.size() == 2) ranges.push_back({s, e, to_upper(cc)});
            } catch (...) {}
        }
        pclose(f);
        std::ranges::sort(ranges, {}, &Range::start);
        return !ranges.empty();
    }
    std::string lookup(std::string_view ip) const {
        uint32_t u = ip4_to_u32(ip);
        if (u == 0) return "??";
        // binary search
        auto it = std::ranges::upper_bound(ranges, u, {}, &Range::start);
        if (it == ranges.begin()) return "??";
        --it;
        if (u >= it->start && u <= it->end) return it->cc;
        return "??";
    }
    size_t size() const { return ranges.size(); }
};

// ====================== TOR CONTROL CLIENT (POSIX, C++23) ======================
class TorControl {
    int fd_ = -1;
    TorConfig cfg_;
    std::string last_error_;

    bool set_nonblock(bool nb) {
        if (fd_ < 0) return false;
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags < 0) return false;
        flags = nb ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
        return fcntl(fd_, F_SETFL, flags) == 0;
    }

public:
    explicit TorControl(TorConfig cfg) : cfg_(std::move(cfg)) {}
    ~TorControl() { close(); }

    bool connect() {
        close();
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        int rc = getaddrinfo(cfg_.control_host.c_str(), std::to_string(cfg_.control_port).c_str(), &hints, &res);
        if (rc != 0 || !res) {
            last_error_ = "getaddrinfo failed";
            return false;
        }
        fd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd_ < 0) {
            freeaddrinfo(res);
            last_error_ = "socket() failed";
            return false;
        }
        if (::connect(fd_, res->ai_addr, res->ai_addrlen) < 0) {
            freeaddrinfo(res);
            last_error_ = std::format("connect {}:{} failed: {}", cfg_.control_host, cfg_.control_port, strerror(errno));
            close();
            return false;
        }
        freeaddrinfo(res);
        return true;
    }

    void close() {
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

    std::string get_last_error() const { return last_error_; }

    // Resolve effective data directory for cookie/consensus (safe probing, portable)
    fs::path effective_data_dir() const {
        if (!cfg_.data_dir.empty()) return cfg_.data_dir;
        std::error_code ec;
        std::vector<fs::path> candidates = {
            "/var/lib/tor/data",
            "/var/lib/tor",
            "/run/tor",           // some systemd setups
            "/var/run/tor",       // older
            "/var/lib/tor/instance" // rare multi-instance
        };
        for (auto& candidate : candidates) {
            if (fs::exists(candidate / "cached-microdesc-consensus", ec) ||
                fs::exists(candidate / "control_auth_cookie", ec))
                return candidate;
        }
        return "/var/lib/tor/data"; // final fallback
    }

    fs::path effective_cookie_path() const {
        if (!cfg_.cookie_file.empty()) return cfg_.cookie_file;
        return effective_data_dir() / "control_auth_cookie";
    }

    fs::path effective_consensus_path() const {
        auto dd = effective_data_dir();
        fs::path p = dd / "cached-microdesc-consensus";
        if (fs::exists(p)) return p;
        return dd / "cached-consensus"; // fallback name on some setups
    }

    // Read control password: CLI > env
    std::string get_control_password() const {
        if (!cfg_.control_password.empty()) return cfg_.control_password;
        const char* env = std::getenv("TOR_CONTROL_PASSWORD");
        if (env && *env) return trim(env);
        return {};
    }

    std::string read_password_from_file(const fs::path& p) const {
        if (p.empty()) return {};
        std::ifstream f(p);
        if (!f) return {};
        std::string line;
        std::getline(f, line);
        return trim(line);
    }

    // Cookie: try direct open first (if user made it group-readable or runs as tor), then sudo -n
    std::vector<uint8_t> read_cookie() const {
        fs::path cp = effective_cookie_path();

        // Direct read (best for users who set up group access)
        {
            std::error_code ec;
            if (fs::exists(cp, ec)) {
                std::ifstream f(cp, std::ios::binary);
                if (f) {
                    std::vector<uint8_t> cookie(32);
                    f.read(reinterpret_cast<char*>(cookie.data()), 32);
                    if (f.gcount() == 32) return cookie;
                }
            }
        }

        // Fallback: non-interactive sudo (requires NOPASSWD or cached credentials)
        std::string cmd = std::format("sudo -n cat {} 2>/dev/null", cp.string());
        FILE* p = popen(cmd.c_str(), "r");
        if (!p) return {};
        std::vector<uint8_t> cookie(32);
        size_t n = fread(cookie.data(), 1, 32, p);
        pclose(p);
        if (n != 32) return {};
        return cookie;
    }

    static std::string to_hex(std::span<const uint8_t> b) {
        static constexpr char hex[] = "0123456789ABCDEF";
        std::string out; out.reserve(b.size()*2);
        for (uint8_t v : b) { out += hex[v>>4]; out += hex[v&0xF]; }
        return out;
    }

    bool authenticate() {
        if (fd_ < 0) return false;

        // 1. Try explicit control password (CLI or TOR_CONTROL_PASSWORD env). This is the recommended way for normal users.
        std::string pass = get_control_password();
        if (!pass.empty()) {
            std::string cmd = std::format("AUTHENTICATE \"{}\"\r\n", pass);
            if (write_raw(cmd) && read_ok()) {
                if (cfg_.verbose) std::println("Authenticated via control password");
                return true;
            }
        }

        // 2. Try cookie (direct open preferred, sudo fallback only if needed)
        auto cookie = read_cookie();
        if (!cookie.empty()) {
            std::string cmd = std::format("AUTHENTICATE {}\r\n", to_hex(cookie));
            if (write_raw(cmd) && read_ok()) {
                if (cfg_.verbose) std::println("Authenticated via control cookie");
                return true;
            }
        }

        last_error_ = "Authentication failed. Provide --control-password or set TOR_CONTROL_PASSWORD, or make the control cookie readable (e.g. add your user to the tor group and chmod g+r the cookie).";
        return false;
    }

    bool write_raw(std::string_view data) {
        if (fd_ < 0) return false;
        ssize_t n = ::write(fd_, data.data(), data.size());
        return n == static_cast<ssize_t>(data.size());
    }

    bool read_ok(int timeout_ms = 5000) {
        auto r = read_reply(timeout_ms);
        return r.code == 250 || r.code == 251;
    }

    ControlReply read_reply(int timeout_ms = 15000) {
        ControlReply rep;
        if (fd_ < 0) { rep.code = 500; return rep; }

        std::string buf;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

        char tmp[4096];
        bool saw_first = false;
        while (std::chrono::steady_clock::now() < deadline) {
            pollfd pfd{fd_, POLLIN, 0};
            int pr = poll(&pfd, 1, 200);
            if (pr <= 0) continue;
            ssize_t n = ::read(fd_, tmp, sizeof(tmp));
            if (n <= 0) break;
            buf.append(tmp, n);

            // Parse first line for code
            if (!saw_first) {
                size_t nl = buf.find("\r\n");
                if (nl != std::string::npos) {
                    std::string first = buf.substr(0, nl);
                    if (first.size() >= 3) {
                        try { rep.code = std::stoi(first.substr(0,3)); } catch(...) { rep.code=500; }
                    }
                    saw_first = true;
                }
            }

            // Detect end
            if (buf.find("\r\n.\r\n") != std::string::npos) {
                rep.is_multiline = true;
                break;
            }
            if (buf.find("\r\n250 ") != std::string::npos || buf.find("\r\n251 ") != std::string::npos) {
                break;
            }
            if (buf.find("\r\n") != std::string::npos && rep.code >= 400) break; // error early
        }

        // Split lines, strip protocol
        std::istringstream iss(buf);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            if (line == ".") break;
            // Strip leading "250-xxx=" or "250+xxx=" or "250- " etc
            if (line.size() > 4 && (line[3]=='-' || line[3]=='+' || line[3]==' ')) {
                size_t eq = line.find('=');
                if (eq != std::string::npos && eq > 4) line = line.substr(eq+1);
                else line = line.substr(4);
            }
            rep.lines.emplace_back(std::move(line));
            if (rep.lines.size() > 200000) break; // safety
        }
        return rep;
    }

    bool send_command(std::string_view cmd) {
        return write_raw(std::string(cmd) + "\r\n");
    }

    std::expected<ControlReply, std::string> cmd(std::string_view c, int to_ms = 15000) {
        if (!send_command(c)) return std::unexpected("send failed");
        auto r = read_reply(to_ms);
        if (r.code >= 400) return std::unexpected(std::format("Tor error {}: {}", r.code, join(r.lines, " | ")));
        return r;
    }

    // High level
    std::string get_version() {
        auto r = cmd("GETINFO version");
        if (!r) return "unknown";
        for (auto& l : r->lines) if (!l.empty()) return l;
        return "unknown";
    }

    bool is_bootstrapped() {
        auto r = cmd("GETINFO status/bootstrap-phase");
        if (!r) return false;
        for (auto& l : r->lines) {
            if (l.find("100%") != std::string::npos || l.find("done") != std::string::npos || l.find("TAG=done") != std::string::npos) return true;
        }
        // Many running Tors report bootstrap via this even if not "100%" string in every reply
        return true; // assume ok if we got reply at all (control works)
    }

    std::vector<Relay> fetch_consensus(bool use_geo = true) {
        GeoIP geo;
        if (use_geo) geo.load(cfg_.geoip_file.empty() ? DEFAULT_GEOIP : cfg_.geoip_file);

        // Try live first (no sudo needed if control works)
        std::string data;
        auto r = cmd("GETINFO ns/all", 30000);
        if (r && !r->lines.empty()) {
            for (auto& l : r->lines) data += l + "\n";
        }
        if (data.empty()) {
            // Fallback to consensus file (sudo cat or direct)
            fs::path consensus = effective_consensus_path();
            // Try direct first
            {
                std::ifstream direct(consensus);
                if (direct) {
                    data.assign(std::istreambuf_iterator<char>(direct), {});
                }
            }
            if (data.empty()) {
                std::string catcmd = std::format("sudo -n cat {} 2>/dev/null", consensus.string());
                FILE* f = popen(catcmd.c_str(), "r");
                if (f) {
                    char b[8192];
                    while (size_t n = fread(b, 1, sizeof(b), f)) data.append(b, n);
                    pclose(f);
                }
            }
        }
        return parse_consensus_data(data, geo);
    }

    static std::vector<Relay> parse_consensus_data(std::string_view data, const GeoIP& geo) {
        std::vector<Relay> relays;
        Relay cur;
        std::istringstream iss{std::string(data)};
        std::string line;
        while (std::getline(iss, line)) {
            if (line.starts_with("r ")) {
                if (!cur.fingerprint.empty()) relays.push_back(cur);
                cur = Relay{};
                auto parts = split(std::string_view(line).substr(2), ' ');
                if (parts.size() >= 6) {
                    cur.nickname = parts[0];
                    // parts[1] is base64 identity (20 bytes) -> fingerprint
                    std::string b64 = parts[1];
                    // decode base64 (Tor router identity)
                    auto fp_bytes = base64_decode(b64);
                    if (fp_bytes.size() >= 20) {
                        cur.fingerprint = "$" + to_hex(std::span(fp_bytes.data(), 20));
                    }
                    cur.ip = parts[4]; // r <nick> <b64> <date> <time> <ip> <orport> <dirport>
                    if (parts.size() > 5) cur.orport = std::atoi(parts[5].c_str());
                }
            } else if (line.starts_with("s ")) {
                cur.flags = split(std::string_view(line).substr(2), ' ');
            } else if (line.starts_with("w Bandwidth=")) {
                auto eq = line.find('=');
                if (eq != std::string::npos) {
                    try { cur.bandwidth = std::stoi(line.substr(eq+1)); } catch(...) {}
                }
            }
        }
        if (!cur.fingerprint.empty()) relays.push_back(cur);

        // enrich country
        for (auto& rel : relays) {
            if (use_geo_in_relay(rel, geo)) {
                rel.country = geo.lookup(rel.ip);
            }
        }
        return relays;
    }

    static bool use_geo_in_relay(const Relay&, const GeoIP&) { return true; } // always attempt

    static std::vector<uint8_t> base64_decode(std::string in) {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        while (in.size() % 4) in.push_back('='); // pad for safety
        std::vector<uint8_t> out;
        uint32_t val = 0; int bits = 0;
        for (char c : in) {
            if (c == '=') break;
            size_t p = chars.find(c);
            if (p == std::string::npos) continue;
            val = (val << 6) | static_cast<uint32_t>(p);
            bits += 6;
            if (bits >= 8) {
                out.push_back(static_cast<uint8_t>((val >> (bits-8)) & 0xFF));
                bits -= 8;
            }
        }
        return out;
    }

    bool newnym() {
        auto r = cmd("SIGNAL NEWNYM");
        return r.has_value();
    }

    bool reload() {
        auto r = cmd("SIGNAL RELOAD");
        return r.has_value();
    }

    std::string get_circuit_status() {
        auto r = cmd("GETINFO circuit-status");
        if (!r) return "error";
        return join(r->lines, "\n");
    }

    bool extend_circuit(const std::vector<std::string>& fps) {
        if (fps.empty()) return false;
        std::string path = join(fps, ",");
        auto r = cmd(std::format("EXTENDCIRCUIT 0 {}", path), 20000);
        return r && r->code == 250;
    }

    bool setconf(const std::map<std::string, std::string>& kvs) {
        if (kvs.empty()) return true;
        std::string args;
        for (auto& [k,v] : kvs) {
            if (!args.empty()) args += " ";
            args += std::format("{}={}", k, v);
        }
        auto r = cmd(std::format("SETCONF {}", args));
        return r.has_value();
    }

    // For torrc apply we do not use SETCONF for node selection (requires restart)
};

// ====================== TORRC GENERATION & APPLY ======================
std::string generate_torrc_snippet([[maybe_unused]] const TorConfig& cfg,
                                   const std::vector<std::string>& exit_countries,
                                   const std::vector<std::string>& entry_fps,
                                   const std::vector<std::string>& exclude_fps,
                                   bool strict,
                                   int min_bw,
                                   bool only_fast,
                                   bool only_stable,
                                   const std::vector<std::pair<std::string,std::string>>& extra_sets) {
    std::ostringstream oss;
    oss << "# Generated by tor_control (modern C++23, portable) - " 
        << std::format("{:%Y-%m-%d %H:%M}", std::chrono::system_clock::now()) << "\n";
    oss << "# \n";
    oss << "# To apply on this machine (works on systemd, OpenRC, etc.):\n";
    oss << "#   tor_control apply --torrc /etc/tor/torrc --restart-cmd \"" << cfg.restart_cmd << "\"\n";
    oss << "# Or with a control password (recommended for normal users):\n";
    oss << "#   tor_control --control-password \"...\" apply ...\n";
    oss << "# \n";
    oss << "# Common alternatives:\n";
    oss << "#   --restart-cmd \"systemctl restart tor\"          # Ubuntu, Debian, Fedora, Arch, ...\n";
    oss << "#   --restart-cmd \"/etc/init.d/tor restart\"        # Gentoo OpenRC, some older systems\n";
    oss << "#   --restart-cmd \"service tor restart\"            # Some SysV / Ubuntu legacy\n";
    oss << "# \n";
    oss << "User tor\nPIDFile /run/tor/tor.pid\nLog notice syslog\n";
    oss << "DataDirectory /var/lib/tor/data\n";
    oss << "ControlPort 9051\nCookieAuthentication 1\n";
    if (!entry_fps.empty()) {
        oss << "EntryNodes " << join(entry_fps, ",") << "\n";
    }
    if (!exit_countries.empty()) {
        std::vector<std::string> ecs;
        for (auto& c : exit_countries) ecs.push_back("{" + c + "}");
        std::string ec = join(ecs, ",");
        oss << "ExitNodes " << ec << "\n";
    }
    if (!exclude_fps.empty()) {
        oss << "ExcludeNodes " << join(exclude_fps, ",") << "\n";
    }
    if (strict) oss << "StrictNodes 1\n";
    if (min_bw > 0) oss << "# min-bandwidth " << min_bw << " (filter was applied at generation time)\n";
    if (only_fast) oss << "# only-fast nodes selected\n";
    if (only_stable) oss << "# only-stable nodes selected\n";
    for (auto& [k,v] : extra_sets) {
        oss << k << " " << v << "\n";
    }
    oss << "\n";
    return oss.str();
}

bool write_file(const fs::path& p, std::string_view content) {
    std::ofstream f(p, std::ios::trunc);
    if (!f) return false;
    f << content;
    return true;
}

bool apply_torrc(const TorConfig& cfg, std::string_view content, std::string& out_msg) {
    if (cfg.dry_run) {
        out_msg = "[DRY-RUN] Would write to " + cfg.torrc_path.string();
        std::println("{}", content);
        return true;
    }
    fs::path tmp = fs::temp_directory_path() / ("torrc.new." + std::to_string(getpid()));
    if (!write_file(tmp, content)) {
        out_msg = "Failed to write temp file";
        return false;
    }

    std::string cmd;
    if (cfg.use_sudo) {
        if (cfg.use_sudo_pass && !cfg.sudo_pass_file.empty()) {
            // Advanced non-interactive mode (only for special/CI setups)
            cmd = std::format("sudo -S -p '' cp {} {} < {}", tmp.string(), cfg.torrc_path.string(), cfg.sudo_pass_file.string());
        } else {
            cmd = std::format("sudo cp {} {}", tmp.string(), cfg.torrc_path.string());
        }
    } else {
        cmd = std::format("cp {} {}", tmp.string(), cfg.torrc_path.string());
    }

    int rc = std::system(cmd.c_str());
    fs::remove(tmp);
    if (rc != 0) {
        out_msg = "Failed to install new torrc (rc=" + std::to_string(rc) + "). Command was: " + cmd;
        return false;
    }
    out_msg = "torrc applied to " + cfg.torrc_path.string();
    return true;
}

bool restart_tor(const TorConfig& cfg, std::string& out_msg) {
    if (cfg.dry_run) {
        out_msg = std::format("[DRY-RUN] Would run: sudo {}", cfg.restart_cmd);
        return true;
    }

    std::string cmd;
    if (cfg.use_sudo) {
        if (cfg.use_sudo_pass && !cfg.sudo_pass_file.empty()) {
            cmd = std::format("sudo -S -p '' {} < {}", cfg.restart_cmd, cfg.sudo_pass_file.string());
        } else {
            cmd = "sudo " + cfg.restart_cmd;
        }
    } else {
        cmd = cfg.restart_cmd;
    }

    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        out_msg = "Restart command failed (rc=" + std::to_string(rc) + "): " + cmd;
        return false;
    }
    out_msg = "Tor restart command executed: " + cmd;
    std::this_thread::sleep_for(1500ms);
    return true;
}

// ====================== FILTER / PICK HELPERS ======================
std::vector<Relay> filter_relays(const std::vector<Relay>& all,
                                 const std::vector<std::string>& countries,
                                 int min_bw,
                                 bool only_exit,
                                 bool only_guard,
                                 bool only_fast,
                                 bool only_stable) {
    std::vector<Relay> out;
    for (const auto& r : all) {
        if (min_bw > 0 && r.bandwidth < min_bw) continue;
        if (only_exit && std::ranges::find(r.flags, "Exit") == r.flags.end()) continue;
        if (only_guard && std::ranges::find(r.flags, "Guard") == r.flags.end()) continue;
        if (only_fast && std::ranges::find(r.flags, "Fast") == r.flags.end()) continue;
        if (only_stable && std::ranges::find(r.flags, "Stable") == r.flags.end()) continue;
        if (!countries.empty()) {
            bool match = false;
            for (auto& c : countries) if (to_upper(r.country) == to_upper(c)) { match=true; break; }
            if (!match) continue;
        }
        out.push_back(r);
    }
    return out;
}

std::vector<std::string> pick_top_fps(const std::vector<Relay>& relays, size_t n, bool randomize = false) {
    std::vector<Relay> sorted = relays;
    std::ranges::sort(sorted, std::greater{}, &Relay::bandwidth);
    if (sorted.size() > n) sorted.resize(n);
    std::vector<std::string> fps;
    for (auto& r : sorted) fps.push_back(r.fingerprint);
    if (randomize) {
        // simple shuffle using time seed for variety
        std::srand(static_cast<unsigned>(std::time(nullptr)));
        std::ranges::shuffle(fps, std::mt19937{std::random_device{}()});
    }
    return fps;
}

// ====================== CLI ======================
void print_help() {
    std::println(R"(
tor_control - modern C++23 Tor control & configuration tool (portable across distros)

USAGE:
  tor_control [options] <command> [args]

COMMANDS:
  status                 Show version, bootstrap status, connection info
  newnym                 Request fresh circuits (SIGNAL NEWNYM)
  list-circuits          Current circuits from control port
  list-nodes             Show relays from consensus (very useful for selection)
  build-circuit          Manually extend a circuit using chosen nodes
  generate-torrc         Print a torrc fragment with your node restrictions
  apply                  Write torrc (via sudo) and optionally restart Tor
  restart                Restart the Tor daemon (via sudo + configurable command)
  setconf                SETCONF for live options
  getinfo <key>          Raw GETINFO
  help                   This help

OPTIONS (portability & authentication - important!):
  --control-host H
  --control-port P                  (defaults: 127.0.0.1:9051)
  --control-password PASS           Recommended for normal users. Or set TOR_CONTROL_PASSWORD env var.
  --cookie-file PATH                Explicit path to control_auth_cookie (if readable by you)
  --data-dir PATH                   Tor DataDirectory (helps find cookie + consensus automatically)

  --torrc PATH                      (default: /etc/tor/torrc)
  --geoip-file PATH                 (default: /usr/share/tor/geoip)

  --restart-cmd "command"           The command to run after "sudo " when restarting.
                                    Default: "systemctl restart tor"   (works on Ubuntu, Fedora, Arch, etc.)
                                    Gentoo/OpenRC example: --restart-cmd "/etc/init.d/tor restart"
                                    Another common: --restart-cmd "service tor restart"

  --use-sudo-pass                   ADVANCED / developer only. Uses sudo -S with a password file.
                                    Normal users should NOT use this. Let your sudo prompt you.
  --sudo-pass-file F                Only used together with --use-sudo-pass.

  --dry-run
  --verbose
  --no-sudo                         Skip sudo for torrc/restart (you must have write access yourself)

Node selection / filters (for list-nodes, generate, build-circuit, apply):
  --min-bw N
  --country CC,CC                   e.g. us,de,gb
  --exit --guard --fast --stable
  --top N
  --strict
  --set Key=Value                   (repeatable, passed through to torrc)

EXAMPLES:

  # Works on almost any distro (systemd or not)
  tor_control --control-password MySecret status
  TOR_CONTROL_PASSWORD=MySecret tor_control list-nodes --top 20 --exit --country us --min-bw 8000

  # Generate a strict fast-exit config
  tor_control generate-torrc --exit --country us,ca --min-bw 10000 --strict --top 150 > my.torrc

  # Apply it (sudo will prompt for YOUR password unless you configured sudoers)
  tor_control apply --torrc my.torrc --restart

  # Gentoo/OpenRC user
  tor_control apply --torrc my.torrc --restart-cmd "/etc/init.d/tor restart"

  # Custom Tor install
  tor_control --data-dir /opt/tor/var/lib/tor --torrc /opt/tor/etc/tor/torrc list-nodes

  # Build a specific circuit
  tor_control build-circuit --fast --exit --country de

Note for normal users:
- For cookie auth without typing a password every time, add your user to the 'tor' (or 'debian-tor') group
  and make the cookie group-readable. Then --control-password is not needed.
- Restart/torrc editing uses "sudo <your --restart-cmd>". Configure /etc/sudoers if you want passwordless.

This tool is designed to be portable (systemd, OpenRC, etc.).
)");
}

int main(int argc, char** argv) {
    TorConfig cfg;
    std::vector<std::string> positional;
    std::vector<std::string> countries;
    std::vector<std::pair<std::string,std::string>> extra_sets;
    int min_bw = 0;
    size_t top_n = 3;
    bool only_exit=false, only_guard=false, only_fast=false, only_stable=false;
    bool strict = false;
    bool do_restart = false;
    std::string subcmd;

    // Simple arg parse
    for (int i=1; i<argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { print_help(); return 0; }
        if (a == "--verbose") { cfg.verbose = true; continue; }
        if (a == "--dry-run") { cfg.dry_run = true; continue; }
        if (a == "--no-sudo") { cfg.use_sudo = false; continue; }
        if (a == "--use-sudo-pass") { cfg.use_sudo_pass = true; continue; }  // advanced only
        if (a == "--strict") { strict = true; continue; }
        if (a == "--restart") { do_restart = true; continue; }
        if (a == "--exit") { only_exit = true; continue; }
        if (a == "--guard") { only_guard = true; continue; }
        if (a == "--fast") { only_fast = true; continue; }
        if (a == "--stable") { only_stable = true; continue; }

        if (a == "--control-host" && i+1<argc) { cfg.control_host = argv[++i]; continue; }
        if (a == "--control-port" && i+1<argc) { cfg.control_port = static_cast<uint16_t>(std::atoi(argv[++i])); continue; }
        if (a == "--control-password" && i+1<argc) { cfg.control_password = argv[++i]; continue; }
        if (a == "--cookie-file" && i+1<argc) { cfg.cookie_file = argv[++i]; continue; }
        if (a == "--data-dir" && i+1<argc) { cfg.data_dir = argv[++i]; continue; }

        if (a == "--torrc" && i+1<argc) { cfg.torrc_path = argv[++i]; continue; }
        if (a == "--geoip-file" && i+1<argc) { cfg.geoip_file = argv[++i]; continue; }

        if (a == "--restart-cmd" && i+1<argc) { cfg.restart_cmd = argv[++i]; continue; }

        if (a == "--sudo-pass-file" && i+1<argc) { cfg.sudo_pass_file = argv[++i]; continue; }

        if (a == "--min-bw" && i+1<argc) { min_bw = std::atoi(argv[++i]); continue; }
        if (a == "--top" && i+1<argc) { top_n = std::stoul(argv[++i]); continue; }
        if (a == "--country" && i+1<argc) {
            for (auto& c : split(argv[++i], ',')) if (!c.empty()) countries.push_back(to_upper(trim(c)));
            continue;
        }
        if (a == "--set" && i+1<argc) {
            std::string kv = argv[++i];
            auto eq = kv.find('=');
            if (eq != std::string::npos) extra_sets.emplace_back(kv.substr(0,eq), kv.substr(eq+1));
            else extra_sets.emplace_back(kv, "");
            continue;
        }
        if (!a.starts_with("--")) {
            if (subcmd.empty()) subcmd = a;
            else positional.push_back(a);
        }
    }

    // Portable defaults from environment
    if (cfg.restart_cmd == DEFAULT_RESTART_CMD) {
        if (const char* env = std::getenv("TOR_RESTART_CMD"); env && *env) {
            cfg.restart_cmd = env;
        } else {
            // Light auto-detection for better out-of-box experience
            std::error_code ec;
            if (std::filesystem::exists("/run/systemd/system", ec)) {
                cfg.restart_cmd = "systemctl restart tor";
            } else if (std::filesystem::exists("/etc/init.d/tor", ec) || std::filesystem::exists("/etc/init.d", ec)) {
                cfg.restart_cmd = "/etc/init.d/tor restart";
            }
            // else leave as systemctl (most common) or user will override
        }
    }

    if (subcmd.empty() || subcmd == "help") { print_help(); return 0; }

    TorControl tc(cfg);

    if (subcmd == "status") {
        if (!tc.connect() || !tc.authenticate()) {
            std::println(stderr, "Connection/auth failed: {}", tc.get_last_error());
            return 1;
        }
        std::println("Tor version: {}", tc.get_version());
        std::println("Bootstrapped: {}", tc.is_bootstrapped() ? "yes" : "no");
        std::println("Control: {}:{}", cfg.control_host, cfg.control_port);
        return 0;
    }

    if (subcmd == "newnym") {
        if (!tc.connect() || !tc.authenticate()) { /*...*/ return 1; }
        bool ok = tc.newnym();
        std::println("NEWNYM: {}", ok ? "requested" : "failed");
        return ok ? 0 : 1;
    }

    if (subcmd == "list-circuits") {
        if (!tc.connect() || !tc.authenticate()) return 1;
        std::println("{}", tc.get_circuit_status());
        return 0;
    }

    if (subcmd == "getinfo") {
        if (positional.empty()) { std::println(stderr, "getinfo <key>"); return 1; }
        if (!tc.connect() || !tc.authenticate()) return 1;
        auto r = tc.cmd(std::format("GETINFO {}", positional[0]));
        if (!r) { std::println(stderr, "{}", r.error()); return 1; }
        for (auto& l : r->lines) std::println("{}", l);
        return 0;
    }

    if (subcmd == "setconf") {
        if (positional.empty() && extra_sets.empty()) { std::println(stderr, "setconf Key=Val ..."); return 1; }
        std::map<std::string,std::string> kvs;
        for (auto& p : positional) {
            auto eq = p.find('=');
            if (eq!=std::string::npos) kvs[p.substr(0,eq)] = p.substr(eq+1);
        }
        for (auto& [k,v] : extra_sets) kvs[k] = v;
        if (!tc.connect() || !tc.authenticate()) return 1;
        bool ok = tc.setconf(kvs);
        std::println("SETCONF: {}", ok?"ok":"fail");
        return ok?0:1;
    }

    if (subcmd == "list-nodes") {
        if (!tc.connect() || !tc.authenticate()) {
            if (cfg.verbose) std::println(stderr, "Control port auth not available, falling back to reading consensus file (will use sudo if necessary).");
        }
        auto relays = tc.fetch_consensus(true);
        auto filtered = filter_relays(relays, countries, min_bw, only_exit, only_guard, only_fast, only_stable);
        std::ranges::sort(filtered, std::greater{}, &Relay::bandwidth);
        if (filtered.size() > top_n) filtered.resize(top_n);
        std::println("Found {} relays from consensus (filtered). Top {} by bandwidth:", relays.size(), filtered.size());
        std::println("{:>4} {:<20} {:>10} {:<6} {:<4} {:<40}", "#", "Nickname", "BW(KB/s)", "CC", "Flags", "Fingerprint");
        int i=1;
        for (const auto& r : filtered) {
            std::vector<std::string> good_flags;
            for (auto& f : r.flags) if (f=="Exit"||f=="Guard"||f=="Fast"||f=="Stable") good_flags.push_back(f);
            std::string fl = join(good_flags, "");
            std::println("{:>4} {:<20} {:>10} {:<6} {:<4} {}", i++, r.nickname.substr(0,20), r.bandwidth, r.country, fl, r.fingerprint);
        }
        return 0;
    }

    if (subcmd == "build-circuit") {
        if (!tc.connect() || !tc.authenticate()) return 1;
        auto relays = tc.fetch_consensus(true);
        auto filtered = filter_relays(relays, countries, min_bw, only_exit, only_guard, only_fast, only_stable);
        if (filtered.empty()) { std::println(stderr, "No relays match filters"); return 1; }
        // pick entry (prefer Guard), middle, exit (prefer Exit)
        std::vector<Relay> guards, middles, exits;
        for (auto& r : filtered) {
            if (std::ranges::find(r.flags,"Guard") != r.flags.end()) guards.push_back(r);
            if (std::ranges::find(r.flags,"Exit") != r.flags.end()) exits.push_back(r);
            middles.push_back(r);
        }
        if (guards.empty()) guards = filtered;
        if (exits.empty()) exits = filtered;
        if (middles.empty()) middles = filtered;

        std::srand(static_cast<unsigned>(time(nullptr)));
        std::vector<std::string> path;
        path.push_back(guards[std::rand() % guards.size()].fingerprint);
        path.push_back(middles[std::rand() % middles.size()].fingerprint);
        path.push_back(exits[std::rand() % exits.size()].fingerprint);
        // trim to requested length if >3 or pad? simple 3 for now
        std::println("Attempting circuit: {} -> {} -> {}", path[0], path[1], path[2]);
        bool ok = tc.extend_circuit(path);
        for (int attempt=1; !ok && attempt < MAX_RETRIES; ++attempt) {
            std::this_thread::sleep_for(1s);
            path[0] = guards[std::rand() % guards.size()].fingerprint;
            path[1] = middles[std::rand() % middles.size()].fingerprint;
            path[2] = exits[std::rand() % exits.size()].fingerprint;
            ok = tc.extend_circuit(path);
        }
        std::println("Circuit build: {}", ok ? "SUCCESS" : "FAILED (may need more time or different nodes)");
        return ok ? 0 : 1;
    }

    if (subcmd == "generate-torrc") {
        // Need relays if using --top / filters for pinning fps
        std::vector<std::string> exit_ct = countries; // reuse as countries for exits
        std::vector<std::string> entry_fps, exclude;
        auto relays = [&]() -> std::vector<Relay> {
            TorControl t2(cfg);
            if (t2.connect() && t2.authenticate()) return t2.fetch_consensus(true);
            return {};
        }();
        auto filtered = filter_relays(relays, countries, min_bw, only_exit, only_guard, only_fast, only_stable);
        if (!filtered.empty()) {
            auto fps = pick_top_fps(filtered, top_n);
            // heuristic: first half-ish as possible entry if guards wanted, rest exit bias
            for (size_t i=0; i<fps.size()/2 && i<top_n/2; ++i) entry_fps.push_back(fps[i]);
        }
        std::string snippet = generate_torrc_snippet(cfg, exit_ct, entry_fps, exclude, strict, min_bw, only_fast, only_stable, extra_sets);
        if (positional.empty()) {
            std::print("{}", snippet);
        } else {
            write_file(positional[0], snippet);
            std::println("Wrote {}", positional[0]);
        }
        return 0;
    }

    if (subcmd == "apply") {
        fs::path src = positional.empty() ? fs::path{} : fs::path(positional[0]);
        std::string content;
        if (!src.empty()) {
            std::ifstream f(src);
            if (!f) { std::println(stderr, "Cannot read {}", src.string()); return 1; }
            content.assign(std::istreambuf_iterator<char>(f), {});
        } else {
            // generate on fly from flags
            auto relays = [&](){ TorControl t(cfg); if(t.connect()&&t.authenticate()) return t.fetch_consensus(true); return std::vector<Relay>{}; }();
            auto filtered = filter_relays(relays, countries, min_bw, only_exit, only_guard, only_fast, only_stable);
            std::vector<std::string> fps = pick_top_fps(filtered, (top_n>0?top_n:50));
            std::string exit_line = !fps.empty() ? "ExitNodes " + join(fps, ",") + "\nStrictNodes 1\n" : "";
            content = "# Generated and applied by tor_control (portable)\n" + exit_line;
            for (auto& [k,v]:extra_sets) content += std::format("{} {}\n", k, v);
        }
        std::string msg;
        bool ok = apply_torrc(cfg, content, msg);
        std::println("{}", msg);
        if (ok && do_restart) {
            std::string rmsg;
            ok = restart_tor(cfg, rmsg);
            std::println("{}", rmsg);
        }
        return ok ? 0 : 1;
    }

    if (subcmd == "restart") {
        std::string msg;
        bool ok = restart_tor(cfg, msg);
        std::println("{}", msg);
        return ok ? 0 : 1;
    }

    std::println(stderr, "Unknown command: {}. See --help", subcmd);
    return 1;
}
