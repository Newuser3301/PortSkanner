# 🛰️ PYRECON

**See the surface. Map the target. Understand the exposure.**

PyRecon is a **low-level network reconnaissance and assessment framework** built for people who care about **how scanning actually works**, not just what buttons to press.

This is not a wrapper around existing tools.  
This is not a shiny UI project.  
This is **raw recon logic, protocol awareness, and controlled scanning** — written to be understood, extended, and trusted.

---

## ⚠️ Read Before Use

PyRecon is designed for:

- Authorized security testing  
- Network reconnaissance and analysis  
- Learning how scanners operate internally  

PyRecon is **not**:
- an exploit framework  
- a malware delivery platform  
- a stealth attack tool  
- a “click-and-own” scanner  

If your goal is exploitation, this tool is intentionally not built for you.

---

## 🔥 Why PyRecon Exists

Most scanners hide complexity.  
PyRecon **exposes it**.

This project exists to show:
- how packets are crafted  
- how ports are probed  
- how services respond  
- how scanners reason about results  

It models **real reconnaissance flow**, not marketing checklists.

---

## 🧠 Core Mentality

- **Recon before action**  
- **Visibility before assumptions**  
- **Protocols over payloads**  
- **Control over automation**  
- **Understanding over speed**  

> If you don’t understand what the scanner is doing, you don’t control it.

---

## 🗂️ Project Structure (Designed, Not Accidental)

```
pyrecon/
├─ core/
│  ├─ compat.py        # runtime flags, imports, feature switches
│  ├─ models.py        # enums and dataclasses
│  ├─ packet.py        # low-level packet crafting
│  └─ scanner.py       # AdvancedScanner logic
├─ engines/
│  └─ scripts.py       # NSE-like script engine
├─ cli.py              # command-line interface
└─ __main__.py         # python -m pyrecon
```

Each component exists for a reason.  
Nothing is hidden behind magic.

---

## 🛰️ Capabilities (Real Recon, No Theater)

### Network Reconnaissance
- TCP scanning (SYN / connect)
- UDP probing with protocol-aware checks
- Port state classification

### Service Fingerprinting
- Banner grabbing
- Signature-based service detection
- Response behavior analysis

### OS & Stack Heuristics
- Lightweight OS fingerprinting
- Network stack behavior analysis

### Scripted Post-Scan Checks
- NSE-like scripting engine
- Extensible post-scan logic
- Controlled execution flow

### Reporting
- Human-readable summaries
- JSON output for tooling
- Nmap-style XML (optional)

---

## 🚫 What PyRecon Deliberately Avoids

❌ Exploitation  
❌ Payload delivery  
❌ Obfuscation tricks  
❌ Automated credential attacks  
❌ “Stealth hacker” theatrics  

This tool focuses on **seeing clearly**, not hiding.

---

## 🛠️ Installation

```bash
git clone https://github.com/Newuser3301/PyRecon.git
cd PyRecon
pip install -r requirements.txt
```

Python **3.9+**

Optional:
- `scapy` for advanced packet crafting
- Elevated privileges for SYN scans (OS-dependent)

---

## ▶️ Usage

```bash
python -m pyrecon <target>
```

For available options:
```bash
python -m pyrecon -h
```

Run only against systems you own or are authorized to assess.

---

## 🎯 Who PyRecon Is For

- Security engineers learning network scanning internals  
- Red-team and blue-team practitioners (recon phase)  
- Python developers building network tools  
- Anyone tired of black-box scanners  

If you want shortcuts, this is not your tool.

---

## 🧪 Project Status

**Active. Low-level. Opinionated.**

Features evolve.  
Architecture improves.  
Principles stay intact.

---

## 🤝 Contributing

Contributions are welcome if they:
- improve protocol handling  
- improve clarity and correctness  
- respect the project’s scope  

Exploit-oriented contributions will be rejected.
