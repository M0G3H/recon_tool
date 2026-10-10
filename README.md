# recon_tool V1.0

<p align="center">
  <img src="https://raw.githubusercontent.com/M0G3H/recon_tool/main/Untitled.png" alt="Recon Tool" width="800">
</p>

A Bash-based security reconnaissance automation toolkit that combines common network and web application assessment tools and can generate an HTML reconnaissance report.

> **Authorization only:** Use this project only against systems you own or have explicit permission to assess. You are responsible for complying with applicable laws, tool licenses, and engagement rules.

## Features

Depending on the selected mode and the tools/data available on your system, `recon_tool` can run:

- **Port and service scanning** 
- **Subdomain and directory fuzzing** 
- **HTTP and web-server information gathering**
- **Burp Suite Export Directory Extraction**
- **Parameter discovery** 
- **URL/JavaScript endpoint extraction** 
- **TLS configuration checks** 
- **WAF fingerprinting** 
- **Template-based checks** 
- **XSS-oriented workflow** 
- **HTTP request-smuggling checks** 
- **HTML report generation** 

## Supported environment

The installer is intended for Debian/Ubuntu/Kali Linux systems.
## Project files

Typical project files:

```text
recon_tool/
├── install.sh
├── recon_tool
├── report_maker.py
└── target.txt
```

The installer copies the project files into:

```text
~/Desktop/recon_tool/
```

## Installation

```bash
git clone https://github.com/M0G3H/recon_tool
cd recon_tool
chmod +x install.sh
sudo bash install.sh
```

The installer uses `sudo` for system package installation and may download source code/templates for third-party tools.
After installation, the project is located at:

```text
~/Desktop/recon_tool/
```

The installer does **not** create a global `recon_tool` command. Launch the script using its path.

## Configure the target

Edit `~/Desktop/recon_tool/target.txt`:

```bash
IP=203.0.113.10
DOMAIN=example.com
COOKIE="optional-session-cookie"
```

Replace the example values with the authorized assessment target.
## Wordlists

The current script expects wordlists at these locations:

```text
~/Desktop/source/dictionary/subs.txt
~/Desktop/source/dictionary/combined_directory.txt
```

The installer creates the dictionary directory but does **not** download these wordlists. Add the files yourself and make sure you have permission to use them. Fuzzing modes may not work correctly until the expected files are present.

## Usage

Run the script from the installed project directory or use its full path:

```bash
cd ~/Desktop/recon_tool
./recon_tool -prtscn
```

The script supports these modes:

| Option | Purpose |
|---|---|
| `-prtscn` | Port/service scanning |
| `-information` | Web and service information gathering |
| `-fuzz` | Subdomain, directory, and parameter discovery |
| `-nuclei` | Nuclei-based checks |
| `-full` | Run the combined workflow |

For the exact options available in your copy, inspect `recon_tool.sh` or run its help option if one is implemented.

## Output and reports

<p align="center">
  <img src="https://raw.githubusercontent.com/M0G3H/recon_tool/main/Screenshot_6.png" alt="Recon Tool" width="800">
</p>

Scan output is stored under a domain-specific directory.
## Third-party projects

This project wraps or installs third-party tools. They are maintained by their respective authors and have their own licenses and usage terms. Review those projects and their documentation:

- [Nmap](https://nmap.org/)
- [ffuf](https://github.com/ffuf/ffuf)
- [Nikto](https://github.com/sullo/nikto)
- [Arjun](https://github.com/s0md3v/Arjun)
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
- [sslscan](https://github.com/rbsec/sslscan)
- [WAFW00F](https://github.com/EnableSecurity/wafw00f)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates)
- [gf](https://github.com/tomnomnom/gf)
- [Dalfox](https://github.com/hahwul/dalfox)
- [Smuggler](https://github.com/defparam/smuggler)
- [JexBoss](https://github.com/joaomatosf/jexboss)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)


## Contributing

Issues and pull requests are welcome. When reporting a bug, include the operating system, the command/mode used, relevant error output, and steps to reproduce. Remove domains, IPs, cookies, tokens, and other sensitive information from logs before sharing.
