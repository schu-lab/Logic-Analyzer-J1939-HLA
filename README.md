# J1939 High-Level Analyzer
Decodes SAE J1939 traffic live inside Logic 2, sitting on top of the built-in CAN analyzer.  
https://en.wikipedia.org/wiki/SAE_J1939

---

## Installation

1. Download / clone this folder (`J1939-HLA/`) to your PC.
2. Open **Logic 2**.
3. Click the **Extensions** button in the right sidebar.
4. Click **"+"** → **"Load Existing Extension"**.
5. Browse to the `J1939-HLA/` folder and confirm.

The extension will appear as **"J1939"** in the analyzer list.

---

## Setup in a Capture

1. **Add the CAN Low-Level Analyzer** to your capture channel.
   - Set the correct bit rate (usually **250 kbps** for heavy-duty J1939).
   - Set the correct bit rate inverted setting if needed (Logic 2 CAN analyzer → "Inverted").

2. **Add the J1939 HLA** on top of it:
   - Click **"+"** in the Analyzers panel → select **J1939**.
   - Set **Input Analyzer** → your CAN analyzer.
   - Choose display preferences in the HLA settings.

3. The Data Table will now show decoded J1939 rows.

---

## HLA Settings

| Setting | Options | Description |
|---|---|---|
| Show 11-bit (Standard) CAN Frames | Hide / Show as Raw CAN | Standard frames are not J1939 — hide or show raw |
| Show TP Fragment Frames | Hide / Show | Show/hide individual BAM announcement and TP.DT data packets |

---

## What Gets Decoded

### Example J1939 Frame
- **PGN** — Parameter Group Number with full name (e.g. `Active Diagnostic Trouble Codes (DM1)`)
- **SA** — Source Address with ECU name (e.g. `Engine #1`, `Transmission #1`)
- **DA** — Destination Address (or `Broadcast`)
- **Priority** — CAN arbitration priority (0–7)
- **Raw bytes** — shown as hex when no signal decoder is available

### Example Signal-Level Decoding
| PGN | Name | Signals Decoded |
|---|---|---|
| 0xF004 | EEC1 | Engine Speed (RPM), Actual Torque (%), Driver Demand Torque (%) |
| 0xFEF1 | CCVS | Wheel-Based Vehicle Speed (km/h), Cruise Control Active |
| 0xFEEF | ET1 | Coolant Temp (°C), Oil Temp (°C), Fuel Temp (°C) |
| 0xFECA | DM1 | MIL/RSL/AWL/Protect lamp status, all active DTCs with SPN/FMI/OC |

### Example DM1 Lamp Status (per J1939-73)
| Value | Meaning |
|---|---|
| OFF | Lamp commanded off |
| ON | Lamp commanded on |
| Special | Short MIL / Class C (WWH-OBD) |
| N/A | Not available / Don't care |

### DTC Encoding (Version 4, CM=0)
SPNs are decoded per J1939-73 Section 5.7.1 Version 4 (current Intel LSB-first format).
Legacy CM=1 frames are also handled and flagged.

---

## Data Table Columns

| Column | Description |
|---|---|
| `summary` | One-line human-readable decode |
| `pgn` | PGN as hex |
| `pgn_name` | Full PGN name |
| `from` | Source ECU name |
| `to` | Destination ECU name (or Broadcast) |
| `priority` | Frame priority |

---

## Source Address & PGN Coverage

Includes the full SAE J1939 source address name table (0x00–0xFF) and 60+ standard PGN names.

---

## Files

```
J1939-HLA/
├── extension.json    — Saleae extension metadata
├── j1939_hla.py      — HLA Python source
└── README.md         — This file
```
