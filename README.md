# The Social-Engineer Toolkit (SET)
* Copyright :copyright: 2020
* Written by: David Kennedy (ReL1K) @HackingDave
* Company: [TrustedSec](https://www.trustedsec.com)

## What is SET?
The Social-Engineer Toolkit (SET) is an open-source offensive security framework that streamlines the creation and delivery of social-engineering campaigns. It packages proven attack primitives—credential harvesting, payload delivery, spear-phishing, USB drops, and more—into a guided interface so red teams can quickly build realistic engagements or awareness training scenarios.

> DISCLAIMER: SET is **only** for authorized testing. Use it exclusively where explicit consent has been granted and all applicable laws, regulations, and policies are followed. Review readme/LICENSE before deploying the toolkit.

### Key capabilities
- Guided console for building end-to-end social-engineering attack chains
- Payload generation and listener management for phishing, USB, wireless, and Java applet vectors
- Web-based capabilities such as credential harvesters, site cloners, and mass mailers
- Extensible module system, API hooks, and automation helpers for custom tradecraft

## Requirements
- Python 3.8+ and pip
- Git (for source installations)
- Linux or macOS (Linux is recommended; macOS support is experimental). Windows users should run SET inside WSL/WSL2.

## Installation

### Kali Linux / Debian-based (including WSL/WSL2)
```bash
sudo apt update
sudo apt install set -y
```
Kali images inside WSL/WSL2 ship lean; the command above pulls the maintained SET package without needing pip.

### Install from source (all platforms)
```bash
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineer-toolkit
python3 -m venv venv        # optional but recommended
source venv/bin/activate    # use venv\Scripts\activate on Windows PowerShell
pip install -r requirements.txt
sudo python3 setup.py install
```
On Windows/WSL use `sudo` where applicable; on macOS provide administrator credentials when prompted. The repository includes helper launchers (`setoolkit`, `seautomate`, etc.) that are installed system-wide.

### macOS (Apple Silicon notes)
Apple Silicon systems should **always** use a virtual environment to ensure native arm64 wheels are used:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo python3 setup.py install
```
If Rosetta-based dependencies are needed, install Xcode command-line tools (`xcode-select --install`) beforehand.

## Usage

### Launch the interactive console
```bash
sudo setoolkit
# or from the repository root
sudo python3 setoolkit
```
You will be greeted with the text-based menu. Navigation follows a number-driven workflow (for example, `1` for Social-Engineering Attacks, `2` for Fast-Track Pen Testing). Each submenu includes contextual help explaining what the selection launches.

### Example: Credential Harvester workflow
```text
1) Social-Engineering Attacks
2) Website Attack Vectors
3) Credential Harvester Attack Method
4) Site Cloner
```
Provide the URL you want to clone and SET will copy it locally, host it, and capture supplied credentials in `~/.set/reports/<timestamp>/`. Use this flow to rehearse phishing-awareness trainings or validate defensive controls.

### Example: Generate a payload via automation
```bash
python3 src/core/payloadgen/create_payloads.py \
  --pwn-type powershell --ip 192.0.2.10 --port 443 --output payload.txt
```
This helper script automates payload creation without launching the full menu, making it easy to script workflows or integrate SET into CI-based red-team pipelines. Run `--help` to see the supported payloads and output formats.

## Documentation and support
- Full manual: [readme/User_Manual.pdf](https://github.com/trustedsec/social-engineer-toolkit/raw/master/readme/User_Manual.pdf)
- Issues and feature requests: [GitHub Issues](https://github.com/trustedsec/social-engineer-toolkit/issues)
- Training and community content: TrustedSec conference workshops, blog posts, and public talks

Please report bugs or enhancement ideas through GitHub Issues with detailed reproduction steps, SET version, and platform information. Ethical use keeps the community strong.
