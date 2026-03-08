# J1939 High-Level Analyzer
Decodes SAE J1939 traffic live inside Logic 2, sitting on top of the built-in CAN analyzer.  
https://en.wikipedia.org/wiki/SAE_J1939

Covers **three tiers of PGN handling** across 119 named PGNs:
- **98 PGNs** with full signal-level decoding (named fields, scaled values, units)
- **21 PGNs** recognized by name, shown with raw hex bytes (no signal decoder)
- All remaining frames shown with raw hex bytes and a generic PGN hex label

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
   - Enable "Inverted" in the CAN LLA settings if the signal looks wrong.

2. **Add the J1939 HLA** on top of it:
   - Click **"+"** in the Analyzers panel → select **J1939**.
   - Set **Input Analyzer** → your CAN analyzer.
   - Choose display preferences in the HLA settings.

3. The Data Table will now show decoded J1939 rows.

---

## Getting a Clean Data Table

Logic 2's Data Table shows rows from **all analyzers** by default — meaning you will see both raw CAN LLA rows (`identifier_field`, `data_field`, `crc_field`, etc.) and the J1939 decoded rows mixed together.

**To show only J1939 decoded rows:**

1. Open the Data Table panel.
2. In the **search/filter box** at the top, type: `j1939`
3. This filters to only rows of type `j1939` — one row per complete decoded frame.

Alternatively, click the **column filter icon** and select only the J1939 analyzer source.

Every J1939 row in the Data Table includes these columns:

| Column | Description |
|---|---|
| `summary` | One-line human-readable decode (primary view) |
| `pgn` | PGN as hex (e.g. `0xF004`) |
| `pgn_name` | Full PGN name (e.g. `Electronic Engine Controller 1 (EEC1)`) |
| `priority` | CAN arbitration priority (0–7) |
| `from` | Source ECU name (e.g. `Engine #1`) |
| `to` | Destination ECU name or `Broadcast` |
| `raw_bytes` | Raw payload as hex |
| `decoded` | Structured signal decode string |
| *(signal columns)* | Per-signal decoded values — vary by PGN (e.g. `speed_rpm`, `actual_torque`) |

---

## HLA Settings

| Setting | Options | Description |
|---|---|---|
| Show 11-bit (Standard) CAN Frames | Hide / Show as Raw CAN | Standard frames are not J1939 — hide or show raw |
| Show TP Fragment Frames | Hide / Show | Show/hide individual BAM announcement and TP.DT data packets |

---

## PGN Coverage

### Tier 1 — Full Signal Decoding (98 PGNs)

These PGNs produce named, scaled signal columns in the Data Table in addition to the base columns above.

#### Engine (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xF004 | EEC1 | Engine Speed (RPM), Actual/Driver Demand/Engine Demand Torque (%), Torque Mode, Starter Mode, Controlling Source Address |
| 0xF005 | EEC2 | Accelerator Pedal Position (%), Engine Load (%), Remote Accel (%), Low Idle Switch, Kickdown |
| 0xF006 | EEC3 | Desired Operating Speed (RPM), Nominal Friction Torque (%), Parasitic Loss (%) |
| 0xF010 | EEC4 | Parasitic Losses (%), TC1 Compressor Inlet Pressure (kPa), VGT Actuator Position (%) |
| 0xF011 | GFR | Intake Air Mass Flow Rate (kg/h), Exhaust Gas Mass Flow Rate (kg/h), Intake Air Volumetric Flow Rate (m³/h) |
| 0xF013 | EEC5 | Exhaust Gas Pressure (kPa), Fuel Valve 1 Position (%), Intake Manifold Pressure (kPa) |
| 0xF034 | EEC6 | Throttle Actuator 1/2 Command (%), Throttle Valve 1 Position (%) |
| 0xFEA8 | EEC7 | Fuel Injection Control Pressure (kPa), Commanded/Actual Fuel Rail Pressure (kPa) |
| 0xFEEF | ET1 | Coolant Temp (°C), Oil Temp (°C), Fuel Temp (°C), Turbo Oil Temp (°C), Intercooler Temp (°C) |
| 0xFEBD | ET2 | Turbo Oil Temp (°C), Piston Oil Temp (°C), Coolant Temp 2 (°C), Fuel Temp 2 (°C), Thermostat Opening (%) |
| 0xFEF7 | EFL/P1 | Oil Pressure (kPa), Oil Level (%), Coolant Pressure (kPa), Coolant Level (%), Fuel Delivery Pressure, Crankcase Pressure |
| 0xFEB4 | EFL/P2 | Injection Control Pressure (kPa), Fuel Rail 1/2 Pressure (kPa), Wastegate Position (%), Turbo Oil Pressure (kPa) |
| 0xFEEB | HOURS | Total Engine Hours (h), Total Engine Revolutions |
| 0xF014 | EH | Engine Hours (re-uses HOURS decoder) |
| 0xFEA9 | ETH | Time at Max Torque (h), Time Motoring (h), Time at Max Power (h), Time at Idle (h) |
| 0xFEEA | TSC1 | Override Control Mode, Requested Speed (RPM), Requested Torque (%), Priority |

#### Transmission & Brakes (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xF002 | EBC1 | Brake Pedal Position (%), ABS Active, ASR Engine/Brake Active |
| 0xF003 | EBC2 | Front Axle Speed (km/h), Relative Wheel Speeds FL/FR (km/h) |
| 0xF007 | ETC1 | Output Shaft Speed (RPM), Input Shaft Speed (RPM), Driveline Engaged, TC Lockup, Shift In Progress, Clutch Slip (%) |
| 0xF008 | ETC2 | Current Gear, Selected Gear, Gear Ratio, Requested/Current Range |
| 0xFEF0 | TF | Trans Oil Temp (°C), Oil Level (%), Level Status, Clutch 1/2 Pressure (kPa), Filter ΔP, TC ΔP |
| 0xFEB0 | TF2 | Trans Oil Temp 2 (°C), Lube Pressure (kPa), Clutch 3/4 Pressure (kPa) |
| 0xFEF6 | TC1 | Forward/Reverse Gear Count, Neutral Ratio |

#### Retarder & Axle (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xF00B | ERC1 | Actual/Intended Retarder Torque (%), Enable Switch, Remote Enable, Coolant Load |
| 0xF00C | ERC2 | Requested Retarder Torque (%), Max Available Torque (%), Road Speed Limit (km/h) |
| 0xF009 | EAC1 | Drive Axle 1/2 Lift Air Pressure (kPa), Diff Lock Status, Load DA1/DA2 (kPa) |
| 0xF00A | EAC2 | Steer Axle Temperature (°C), Lube Pressure (kPa), TC Override Switch |

#### Steering & Suspension (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFEC3 | ESC | Steering Wheel Angle (°), Turn Counter, Rotational Velocity (rpm) |
| 0xFE6E | ASC1 | Drive/Steer Axle Target Height (mm), Suspension Control State |
| 0xFE6F | ASC2 | Front-Left/Right & Rear-Left/Right Air Spring Pressure (kPa) |

#### Cruise Control & Vehicle Speed (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFEF1 | CCVS | Wheel-Based Speed (km/h), CC Active/Enable/SetSpeed/Switches, Brake Switch, Clutch Switch |
| 0xFEF9 | CCSS | Max Vehicle Speed (km/h), CC High/Low Set Limits (km/h), Preset Speeds 1/2 (km/h) |

#### Fuel & Economy (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFEF2 | LFE | Fuel Rate (L/h), Instantaneous Fuel Economy (km/L), Average Fuel Economy (km/L), Throttle Position (%) |
| 0xFEE9 | LFC | Trip Fuel (L), Total Fuel Used (L) |
| 0xF020 | GFC | Trip Gaseous Fuel Used (kg), Total Gaseous Fuel Used (kg) |
| 0xFEC0 | GFC2 | Trip Gaseous Fuel Used 2 (kg), Total Gaseous Fuel Used 2 (kg) |
| 0xFEB5 | GFE | Gaseous Fuel Rate (kg/h), Instantaneous Gaseous Economy (km/kg), Average Gaseous Economy (km/kg) |
| 0xFEB6 | AGFE | Average Gaseous Fuel Economy since Reset (km/kg), Lifetime Average (km/kg) |
| 0xFEF8 | PTO | PTO State, PTO Speed (RPM), Set Speed (RPM), Output Shaft Speed (RPM) |
| 0xFEFB | FSP | Fuel Supply Pressure (kPa), Fuel Filter ΔP (kPa) |
| 0xFEFE | WFI | Water In Fuel, Pre/Final Filter Differential Pressure |
| 0xFEED | IO | Total Engine Idle Hours (h), Total Engine Idle Fuel Used (L) |
| 0xFEC2 | HRETF | High-Resolution Engine Trip Fuel (L), Total Fuel Used (L) |

#### Distance & Time (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFEE0 | VD | Trip Distance (km), Total Vehicle Distance (km) |
| 0xFEC1 | HRVD | High-Resolution Trip Distance (km), Total Distance (km) |
| 0xFEE5 | TD | Date (YYYY-MM-DD) and Time (HH:MM:SS) with timezone offset |

#### Ambient & Climate (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFEF3 | AMB | Ambient Air Temp (°C), Cab Temp (°C), Barometric Pressure (kPa), Air Inlet Temp/Pressure, Road Temp (°C) |
| 0xFEF4 | IC1 | Boost Pressure (kPa), Intake Manifold Temp (°C), Exhaust Gas Temp (°C), Air Inlet Pressure, Filter ΔP |
| 0xFEFC | CI | Cab Interior Lighting (%), Dashboard Illumination (%), Main Light Switch |
| 0xFEFD | CCC | HVAC Mode, Target Cab Temperature (°C), Fan Speed (%) |

#### Electrical & Power (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFEF5 | VEP1 | Battery Voltage (V), Charging Voltage (V), Battery Current (A), Alternator Current (A) |
| 0xFEFF | BT | Battery 1 Temperature (°C), Battery 2 Temperature (°C) |
| 0xFD09 | BMSH | Battery Main Switch Hold Request |

#### Vehicle Information & Hours (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFEEC | VI | Vehicle Identification Number (VIN string, via TP reassembly) |
| 0xFEEE | VH | Total Vehicle Hours (h), Total PTO Hours (h) |
| 0xFEFA | TIRE | Tire Location, Pressure (kPa), Temperature (°C) |
| 0xFEE3 | SOFT | Software Identification string(s) (via TP, `*`-delimited) |
| 0xFEE4 | ECUH | ECU Power Cycle Count, Total Operating Hours (h) |

#### Aftertreatment / Emissions (J1939-71)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFD7D | AEGR1 | EGR Valve Position (%), EGR Temperature (°C) |
| 0xFDB5 | AT1T1I | DEF Tank Level (%), DEF Temperature (°C), DEF Volume (L), DEF Concentration (%) |
| 0xFDB8 | AT1PSDP | DPF Differential Pressure (kPa), Outlet Temperature (°C), Soot Load Regen Threshold (%) |
| 0xFDB9 | ATPFDC | DPF Active/Passive Regeneration Status, Regeneration Inhibit Switch |
| 0xFDBA | AT1OG | SCR Outlet NOx (ppm), SCR Outlet NH3 (ppm), Outlet Temperature (°C) |

#### Diagnostics — Core (J1939-73)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xFECA | DM1 | MIL/RSL/AWL/Protect lamp status; all active DTCs with SPN, FMI, OC + FMI description |
| 0xFECB | DM2 | Previously active DTCs (same structure as DM1) |
| 0xFECC | DM3 | Diagnostic Data Clear/Reset broadcast |
| 0xFECD | DM4 | Freeze Frame Parameters — lamp status + DTCs at time of fault |
| 0xFECE | DM5 | Active/Previous lamp counts, OBD compliance type, monitor readiness |
| 0xFECF | DM6 | Emission-related pending DTCs (same structure as DM1) |
| 0xFED0 | DM7 | Command Non-Continuous Monitor Test — Test ID, SPN, FMI |
| 0xFED8 | DM8 | Test Results — Test ID, SPN, FMI, Test Value, Limit Value |
| 0xFED2 | DM9 | Emission-Related Permanent DTCs (same structure as DM1) |
| 0xFED3 | DM10 | Emission-Related Pending DTCs 2 (same structure as DM1) |
| 0xFED4 | DM11 | Emission Diagnostic Data Clear/Reset broadcast |
| 0xFED5 | DM12 | Emission-Related Active DTCs (same structure as DM1) |
| 0xFED6 | DM13 | Stop/Start Broadcast — Hold Signal, Current/Requested Data Link |
| 0xFED7 | DM14 | Memory Access Request — Command (Read/Write/Erase), Address, Length, Security Level |
| 0xFED9 | DM15 | Memory Access Response — Status, Address, Length |
| 0xFEDA | DM16 | Binary Data Transfer — byte count + hex payload |
| 0xFEDB | DM21 | Distance/Time with MIL active, Distance/Time since DTCs cleared |
| 0xFEDC | DM22 | Individual DTC Clear/Reset — Control, SPN/FMI/OC |
| 0xFEDD | DM23 | Emission-Related Previously Active DTCs (same structure as DM1) |
| 0xFEDE | DM24 | SPN Support list — SPN, Data Length, SPNs in order |
| 0xFEDF | DM25 | Expanded Freeze Frame — lamp status + DTCs |
| 0xDF00 | DM26 | Diagnostic Readiness 3 — Time Since Engine Start, Warm-Up Count, Continuous Monitor readiness |
| 0xFEE1 | DM27 | All Pending DTCs (same structure as DM1) |
| 0xFEE2 | DM28 | Permanent DTCs (same structure as DM1) |
| 0xD300 | DM29 | Regulated Exhaust Emission Levels — Active/Pending/Permanent/MIL DTC counts |
| 0xD400 | DM30 | Scaled Test Results — Test ID, SPN, FMI, Test Value, Min/Max Limits |
| 0xD500 | DM31 | DTC-to-Lamp Association — SPN, FMI, Lamp bits |
| 0xD600 | DM32 | Exhaust Emission Exceedance — Exceedance Status, Exceedance Time (s) |
| 0xD700 | DM33 | Emission Increasing AECD Active Time — AECD number + Engine Hours per entry |
| 0xD800 | DM34 | NTE Status — Carve-Out Zone, Control Area, Manufacturer Override |
| 0xD900 | DM35 | Immediate Fault Status (same structure as DM1) |
| 0xDA00 | DM36 | DTC Counts — Active, Previously Active, Pending, Permanent |

#### Network Management (J1939-21)

| PGN | Name | Signals Decoded |
|---|---|---|
| 0xEE00 | AC | Address Claim NAME: Manufacturer Code, Function, Vehicle System, Industry Group, Identity Number, Self-Configuring |
| 0xEA00 | Request | Requested PGN name |
| 0xE800 | ACK | ACK/NACK type and acknowledged PGN name |

---

### Tier 2 — Named, Raw Bytes Only (21 PGNs)

These PGNs are recognized and named in the Data Table (`pgn_name` column shows the correct name, `raw_bytes` shows the hex payload), but no signal decoder is implemented. No per-signal columns are produced.

| PGN | Name | Notes |
|---|---|---|
| 0xEC00 | TP.CM — Transport Protocol Connection Mgmt | Handled internally for BAM reassembly; not emitted as a standalone row unless TP fragments are shown |
| 0xEB00 | TP.DT — Transport Protocol Data Transfer | Same — individual packets surfaced only when "Show TP Fragments" is enabled |
| 0xEF00 | Proprietary A | Peer-to-peer manufacturer-defined; no standard signal layout |
| 0xF000 | Cab Message 1 (CM1) | No decoder implemented |
| 0xF001 | Cab Message 2 (CM2) | No decoder implemented |
| 0xFE56 | Operator Seat Direction Switch (OSD) | No decoder implemented |
| 0xFEBC | Hydraulic Pressure (HP) | No decoder implemented |
| 0xFEBE | Forward Road Image Processing (FRIP) | No decoder implemented |
| 0xFEC4 | Engine Hours (EH2) | No decoder implemented |
| 0xFEC5 | Electronic Transmission Controller 3 (ETC3) | No decoder implemented |
| 0xFEC6 | Electronic Transmission Controller 4 (ETC4) | No decoder implemented |
| 0xFEC7 | Electronic Transmission Controller 5 (ETC5) | No decoder implemented |
| 0xFEC8 | Electronic Transmission Controller 6 (ETC6) | No decoder implemented |
| 0xFEC9 | Electronic Transmission Controller 7 (ETC7) | No decoder implemented |
| 0xFEE6 | Vehicle Hours 2 (VH2) | No decoder implemented |
| 0xFF00–0xFFFF | Proprietary B | Manufacturer-defined; no standard signal layout — requires an OEM `.dbc` or `.sym` file to decode |
| 0xDB00 | DM17 — Boot Load Data | Less common; no decoder implemented |
| 0xDC00 | DM18 — Data Security | Less common; no decoder implemented |
| 0xDD00 | DM19 — Calibration Information | Less common; no decoder implemented |
| 0xDE00 | DM20 — Monitor Performance Ratio | Less common; no decoder implemented |
| 0xE000 | Node Specific (Peer-to-Peer base) | Generic peer-to-peer range; no standard signal layout |

---

### Tier 3 — Unknown PGNs

Any PGN not covered by Tier 1 or Tier 2 will still produce a row in the Data Table. The `pgn` column shows the raw hex value (e.g. `PGN 0x1234`), `from` shows the source address name, and `raw_bytes` shows the full payload. No name or signal decoding is available.

---

## DM1 / DM2 Lamp Status (per J1939-73)

| Value | Meaning |
|---|---|
| OFF | Lamp commanded off |
| ON | Lamp commanded on |
| Special | Short MIL / Class C (WWH-OBD) |
| N/A | Not available / Don't care |

## DTC Encoding (Version 4, CM=0)
SPNs are decoded per J1939-73 Section 5.7.1 Version 4 (current Intel LSB-first format).  
Legacy CM=1 frames are also handled and flagged.  
All 32 FMI descriptions are included per J1939-73 Appendix A.

---

## Transport Protocol (Multi-Packet)

BAM (Broadcast Announce Message) sessions are automatically reassembled. Once all TP.DT packets are received, the complete payload is decoded using the same signal decoders as single-frame messages (e.g. VIN via PGN 0xFEEC, Software ID via 0xFEE3). Individual TP fragments can optionally be shown via the HLA settings.

---

## Source Address Coverage

Includes the full SAE J1939 source address name table (0x00–0xFF). Any address not in the standard table is shown as `SA 0xNN`.

---

## Files

```
J1939-HLA/
├── extension.json  — Saleae extension metadata
├── j1939_hla.py    — HLA Python source (fully self-contained)
└── README.md       — This file
```
