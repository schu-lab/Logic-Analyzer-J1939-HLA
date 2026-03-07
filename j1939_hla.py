# =============================================================================
# J1939 High-Level Analyzer for Saleae Logic 2
# =============================================================================
# Sits on top of Logic 2's built-in CAN low-level analyzer.
# Decodes J1939 extended (29-bit) frames:
#   - Priority, PGN, Destination Address, Source Address
#   - Human-readable PGN names
#   - Signal-level decoding for EEC1, CCVS, ET1, DM1
#   - Transport Protocol BAM reassembly (multi-packet messages)
#
# Installation:
#   1. In Logic 2, open the Extensions panel (right sidebar)
#   2. Click "+" → "Load Existing Extension"
#   3. Point to the folder containing this file and extension.json
#   4. Add the built-in CAN analyzer to your capture (set bit rate, e.g. 250kbps)
#   5. Add "J1939" HLA and select the CAN analyzer as its input
# =============================================================================

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# ---------------------------------------------------------------------------
# J1939 PGN lookup table
# ---------------------------------------------------------------------------
PGN_NAMES = {
    0x00EE00: "Address Claim (AC)",
    0x00EF00: "Proprietary A (ProprietaryA)",
    0x00F000: "Cab Message 1 (CM1)",
    0x00F001: "Cab Message 2 (CM2)",
    0x00F002: "Electronic Brake Controller 1 (EBC1)",
    0x00F003: "Electronic Brake Controller 2 (EBC2)",
    0x00F004: "Electronic Engine Controller 1 (EEC1)",
    0x00F005: "Electronic Engine Controller 2 (EEC2)",
    0x00F006: "Electronic Engine Controller 3 (EEC3)",
    0x00F007: "Electronic Transmission Controller 1 (ETC1)",
    0x00F008: "Electronic Transmission Controller 2 (ETC2)",
    0x00F009: "Electronic Axle Controller 1 (EAC1)",
    0x00F00A: "Electronic Axle Controller 2 (EAC2)",
    0x00F00B: "Electronic Retarder Controller 1 (ERC1)",
    0x00F00C: "Electronic Retarder Controller 2 (ERC2)",
    0x00FECA: "Active Diagnostic Trouble Codes (DM1)",
    0x00FECB: "Previously Active DTCs (DM2)",
    0x00FECC: "Diagnostic Data Clear (DM3)",
    0x00FECE: "Diagnostic Readiness 1 (DM5)",
    0x00FECf: "Emission Pending DTCs (DM6)",
    0x00FED0: "DM7 - Command Non-Continuous Monitor Test",
    0x00FED8: "DM8 - Test Results",
    0x00FEDB: "Diagnostic Readiness 2 (DM21)",
    0x00FEEB: "Engine Hours/Revolutions (HOURS)",
    0x00FEEC: "Vehicle Identification (VI)",
    0x00FEED: "Idle Operation (IO)",
    0x00FEEE: "Vehicle Hours (VH)",
    0x00FEEF: "Engine Temperature 1 (ET1)",
    0x00FEF0: "Transmission Fluids 1 (TF)",
    0x00FEF1: "Cruise Control/Vehicle Speed (CCVS)",
    0x00FEF2: "Fuel Economy (LFE)",
    0x00FEF3: "Ambient Conditions (AMB)",
    0x00FEF4: "Intake/Exhaust Conditions 1 (IC1)",
    0x00FEF5: "Vehicle Electrical Power 1 (VEP1)",
    0x00FEF6: "Transmission Configuration (TC1)",
    0x00FEF7: "Engine Fluid Level/Pressure 1 (EFL/P1)",
    0x00FEF8: "Power Takeoff Information (PTO)",
    0x00FEF9: "Cruise Control/Vehicle Speed Setup (CCSS)",
    0x00FEFA: "Tire Condition (TIRE)",
    0x00FEFB: "Fuel Supply Pressure (FSP)",
    0x00FEFC: "Cab Illumination Message (CI)",
    0x00FEFD: "Cab Climate Control (CCC)",
    0x00FEFE: "Water in Fuel Indicator (WFI)",
    0x00FEFF: "Battery Temperature (BT)",
    0x00FF00: "Proprietary B base",
    0x00EC00: "TP.CM - Transport Protocol Connection Mgmt",
    0x00EB00: "TP.DT - Transport Protocol Data Transfer",
    0x00EA00: "Request PGN",
    0x00E800: "Acknowledgement (ACK/NACK)",
    0x00E000: "Node Specific (Peer-to-Peer base)",
    0x00F010: "Electronic Engine Controller 4 (EEC4)",
    0x00F011: "Engine Gas Flow Rate (GFR)",
    0x00F013: "Electronic Engine Controller 5 (EEC5)",
    0x00F014: "Engine Hours (EH)",
    0x00F020: "Fuel Consumption (Gaseous) (GFC)",
    0x00F034: "Electronic Engine Controller 6 (EEC6)",
    0x00FD09: "Battery Main Switch Hold Request (BMSH)",
    0x00FD7D: "Engine Exhaust Gas Recirculation (AEGR1)",
    0x00FDB5: "Aftertreatment 1 Diesel Exhaust Fluid Tank (AT1T1I)",
    0x00FDB8: "Aftertreatment 1 Diesel Particulate Filter (AT1PSDP)",
    0x00FDB9: "Aftertreatment Diesel Particulate Filter (ATPFDC)",
    0x00FDBA: "Aftertreatment 1 Outlet Gas (AT1OG)",
}

# ---------------------------------------------------------------------------
# Source Address lookup table
# ---------------------------------------------------------------------------
SA_NAMES = {
    0x00: "Engine #1",
    0x01: "Engine #2",
    0x02: "Turbocharger",
    0x03: "Transmission #1",
    0x04: "Transmission #2",
    0x05: "Electrical Charging System",
    0x06: "Axle Steering",
    0x07: "Axle Drive",
    0x08: "Brakes System Controller",
    0x09: "Retarder, Exhaust",
    0x0A: "Retarder, Driveline",
    0x0B: "Cruise Control",
    0x0C: "Fuel System",
    0x0D: "Steering Controller",
    0x0E: "Suspension - Steer Axle",
    0x0F: "Instrument Cluster #1",
    0x10: "Trip Recorder",
    0x11: "Cab Climate Control",
    0x12: "Aerodynamic Control",
    0x13: "Forward Road Image Processing",
    0x14: "Tire Pressure Control",
    0x15: "Ignition Control Module #1",
    0x16: "Ignition Control Module #2",
    0x17: "Seat Control #1",
    0x18: "Lighting Operator Controls",
    0x19: "Rear Axle Steering",
    0x1C: "Body Controller",
    0x1D: "Auxiliary Valve Control",
    0x1E: "Hitch Control",
    0x1F: "Power Take-Off (PTO)",
    0x20: "Off Vehicle Gateway",
    0x21: "Virtual Terminal (In Cab)",
    0x22: "Management Computer #1",
    0x23: "Prop Valve Ctrl, Hydraulic Sys",
    0x24: "Lighting Controller",
    0x25: "Cab Display",
    0x26: "Tractor/Trailer Bridge",
    0x27: "Body-to-Vehicle Interface Control",
    0x28: "Articulation Turntable Control",
    0x29: "Diagnostic Equipment",
    0x2A: "Fasten Seat Belt",
    0x2B: "Air Compressor",
    0x2C: "Safety Restraint System",
    0x2D: "Cab Controller - Primary",
    0x2E: "Cab Controller - Secondary",
    0x2F: "Tire Pressure Monitor",
    0x30: "Ignition Control Module #3",
    0x31: "Engine Injection Control",
    0x32: "Exhaust Emission Controller",
    0x33: "Vehicle Dynamic Stability Controller",
    0x34: "Oil Sensor",
    0x35: "Suspension - Drive Axle #1",
    0x36: "Information System Controller #1",
    0x37: "Ramp/Lift Control",
    0x38: "Chassis Controller",
    0x39: "Fuel Sensor",
    0x3A: "Engine Valve Controller",
    0x3B: "Chassis Display",
    0x3C: "Headway Controller",
    0x3D: "Off Board Diagnostic Unit",
    0x3E: "Data Logger",
    0x3F: "Turbocharger Compressor Bypass",
    0x40: "Parking Brake Controller",
    0x41: "Suspension - Drive Axle #2",
    0x42: "Suspension - Trailer Axle",
    0x43: "Pneumatic System Controller",
    0x44: "Fan Drive Controller",
    0x45: "Steering Column Unit",
    0x46: "Body-to-Vehicle Gateway #1",
    0x47: "Body-to-Vehicle Gateway #2",
    0x48: "Clutch/Converter Unit",
    0x49: "Auxiliary Heater #1",
    0x4A: "Auxiliary Heater #2",
    0x4B: "Engine #3",
    0x4C: "Engine #4",
    0x4D: "Auxiliary Governor",
    0x4E: "Body Controller #2",
    0x4F: "Forward Road Image Processor",
    0x50: "Proximity Detector - Front",
    0x51: "Proximity Detector - Rear",
    0x52: "Roof Controller #1",
    0x53: "Roof Controller #2",
    0x54: "Transmission Display - Primary",
    0x55: "Transmission Display - Secondary",
    0x56: "Exhaust Emission Controller #2",
    0x57: "Headway Controller #2",
    0x58: "Hydraulic Pump Controller",
    0x59: "Suspension - System Controller #1",
    0x5A: "Pneumatic System Controller #2",
    0x5B: "Power Take-Off (Rear/Primary)",
    0x5C: "Off Board Diagnostic Unit #2",
    0x5D: "Door Controller #1",
    0x5E: "Door Controller #2",
    0x5F: "Door Controller #3",
    0x60: "Articulation Control",
    0x61: "Retarder, Exhaust, Engine #1",
    0x62: "Retarder, Exhaust, Engine #2",
    0x63: "Parking Brake Controller",
    0x64: "Axle, Steering, Rear #1",
    0x65: "Axle, Steering, Rear #2",
    0x66: "Differential Lock Controller",
    0x67: "Low Voltage Disconnect",
    0x68: "Roadway Information",
    0x69: "Cab Display #2",
    0x6A: "Engine #5",
    0x6B: "Tachograph",
    0x6C: "Fuel System #2",
    0x6D: "Gaseous Fuel Controller",
    0x6E: "Engine Information System",
    0x6F: "Generator/Alternator",
    0x70: "Suspension - Pneumatic",
    0x71: "Power Take-Off (Front Secondary)",
    0x72: "Off-board Programming Station",
    0x73: "Engine Control Module",
    0x74: "Instrument Cluster #2",
    0x75: "Door Controller #4",
    0x76: "Door Controller #5",
    0x77: "Door Controller #6",
    0x78: "Tire Pressure Controller #2",
    0x79: "Ignition Control Module #4",
    0x7A: "Seat Control #2",
    0x7B: "Lighting Operator Controls #2",
    0x7C: "Rear Axle Steering #2",
    0x7D: "Suspension - Drive Axle #3",
    0x7E: "Suspension - Drive Axle #4",
    0x7F: "Turbocharger Compressor Bypass #2",
    0x80: "Brake Controller",
    0xF9: "On Board Diagnostic Unit",
    0xFA: "Data Logger",
    0xFB: "Reserved",
    0xFC: "SAE Reservation",
    0xFD: "Manufacturer Defined",
    0xFE: "Null Address",
    0xFF: "Global/Broadcast",
}

# ---------------------------------------------------------------------------
# FMI descriptions per J1939-73 Appendix A
# ---------------------------------------------------------------------------
FMI_DESCRIPTIONS = {
    0:  "Data valid but above normal range (most severe)",
    1:  "Data valid but below normal range (most severe)",
    2:  "Data erratic, intermittent or incorrect",
    3:  "Voltage above normal / shorted high",
    4:  "Voltage below normal / shorted low",
    5:  "Current below normal / open circuit",
    6:  "Current above normal / shorted to ground",
    7:  "Mechanical system not responding",
    8:  "Abnormal frequency, pulse width or period",
    9:  "Abnormal update rate",
    10: "Abnormal rate of change",
    11: "Root cause not known",
    12: "Bad intelligent device or component",
    13: "Out of calibration",
    14: "Special instructions",
    15: "Data valid but above normal range (least severe)",
    16: "Data valid but above normal range (moderately severe)",
    17: "Data valid but below normal range (least severe)",
    18: "Data valid but below normal range (moderately severe)",
    19: "Received network data in error",
    20: "Data drifted high",
    21: "Data drifted low",
    31: "Condition exists",
}


# ---------------------------------------------------------------------------
# PGN signal decoders
# ---------------------------------------------------------------------------

def _lamp(bits2):
    return {0b00: "OFF", 0b01: "ON", 0b10: "Special", 0b11: "N/A"}.get(bits2, "?")


def decode_eec1(data):
    """PGN 0xF004 - Electronic Engine Controller 1"""
    if len(data) < 8:
        return None
    speed_raw = data[3] | (data[4] << 8)
    actual_torque = data[2]
    driver_demand = data[1]
    torque_mode = data[0] & 0x0F

    speed_str = f"{speed_raw * 0.125:.1f} RPM" if speed_raw != 0xFFFF else "N/A"
    torque_str = f"{actual_torque - 125}%" if actual_torque != 0xFF else "N/A"
    demand_str = f"{driver_demand - 125}%" if driver_demand != 0xFF else "N/A"

    return {
        "decoded":   f"Speed={speed_str}  Torque={torque_str}  Demand={demand_str}",
        "speed_rpm": speed_str,
        "torque":    torque_str,
        "demand":    demand_str,
        "mode":      f"0x{torque_mode:X}",
    }


def decode_ccvs(data):
    """PGN 0xFEF1 - Cruise Control / Vehicle Speed"""
    if len(data) < 8:
        return None
    speed_raw = data[1] | (data[2] << 8)
    speed_kmh = speed_raw * (1.0 / 256.0)
    speed_str = f"{speed_kmh:.2f} km/h" if speed_raw != 0xFFFF else "N/A"
    cc_active = "Yes" if (data[0] & 0x01) else "No"
    return {
        "decoded":     f"Speed={speed_str}  CC={cc_active}",
        "speed_km_h":  speed_str,
        "cruise_ctrl": cc_active,
    }


def decode_et1(data):
    """PGN 0xFEEF - Engine Temperature 1"""
    if len(data) < 8:
        return None
    coolant = data[0]
    fuel    = data[1]
    oil     = data[3]

    def t(v):
        return f"{v - 40}°C" if v != 0xFF else "N/A"

    return {
        "decoded":      f"Coolant={t(coolant)}  Oil={t(oil)}  Fuel={t(fuel)}",
        "coolant_temp": t(coolant),
        "oil_temp":     t(oil),
        "fuel_temp":    t(fuel),
    }


def decode_dm1(data):
    """PGN 0xFECA - Active Diagnostic Trouble Codes
    Per J1939-73 Section 5.7.1 (Version 4 encoding, CM=0, Intel LSB-first)
    """
    if len(data) < 2:
        return None
    b1, b2 = data[0], data[1]

    mil  = _lamp((b1 >> 6) & 0x3)
    rsl  = _lamp((b1 >> 4) & 0x3)
    awl  = _lamp((b1 >> 2) & 0x3)
    prot = _lamp((b1 >> 0) & 0x3)

    lamps = f"MIL={mil} RSL={rsl} AWL={awl} Prot={prot}"

    # No-DTC condition: bytes 3-6 all zero
    if len(data) >= 6 and data[2:6] == [0, 0, 0, 0]:
        return {"decoded": f"DM1: No faults | {lamps}", "lamps": lamps, "dtcs": "None"}

    dtc_parts = []
    i = 2
    while i + 3 < len(data):
        b3, b4, b5, b6 = data[i], data[i+1], data[i+2], data[i+3]
        cm = (b6 >> 7) & 0x1
        oc = b6 & 0x7F
        if cm == 0:
            spn = b3 | (b4 << 8) | ((b5 >> 5) << 16)
            fmi = b5 & 0x1F
        else:
            spn = b3 | (b4 << 8) | ((b5 & 0x07) << 16)
            fmi = (b5 >> 3) & 0x1F
        oc_s = "N/A" if oc == 127 else str(oc)
        fmi_desc = FMI_DESCRIPTIONS.get(fmi, f"FMI {fmi}")
        dtc_parts.append(f"SPN{spn}/FMI{fmi}({fmi_desc})/OC={oc_s}")
        i += 4

    dtcs_str = " | ".join(dtc_parts) if dtc_parts else "None"
    return {
        "decoded": f"DM1: {len(dtc_parts)} DTC(s) | {lamps}",
        "lamps":   lamps,
        "dtcs":    dtcs_str,
    }


# Map PGN → decoder function
PGN_DECODERS = {
    0x00F004: decode_eec1,
    0x00FEF1: decode_ccvs,
    0x00FEEF: decode_et1,
    0x00FECA: decode_dm1,
}


# ---------------------------------------------------------------------------
# Transport Protocol reassembly
# ---------------------------------------------------------------------------

class _TPSession:
    def __init__(self, pgn, total_bytes, num_packets, start_time):
        self.pgn         = pgn
        self.total_bytes = total_bytes
        self.num_packets = num_packets
        self.start_time  = start_time
        self.packets     = {}   # seq_num (1-based) → 7-byte payload list

    def add_packet(self, seq, payload):
        self.packets[seq] = payload

    def is_complete(self):
        return len(self.packets) >= self.num_packets

    def reassemble(self):
        data = []
        for i in range(1, self.num_packets + 1):
            data.extend(self.packets.get(i, [0xFF] * 7))
        return data[:self.total_bytes]


# ---------------------------------------------------------------------------
# HLA class
# ---------------------------------------------------------------------------

class J1939Hla(HighLevelAnalyzer):
    """J1939 High-Level Analyzer — decodes J1939 frames from Logic 2 CAN LLA."""

    # ── Settings shown in Logic 2 UI ─────────────────────────────────────────
    show_standard_frames = ChoicesSetting(
        label="Show 11-bit (Standard) CAN Frames",
        choices=("Hide", "Show as Raw CAN")
    )

    show_tp_fragments = ChoicesSetting(
        label="Show TP Fragment Frames (TP.CM / TP.DT)",
        choices=("Hide", "Show")
    )

    # ── Output frame display templates ───────────────────────────────────────
    result_types = {
        "j1939": {
            "format": "{{data.summary}}"
        },
        "j1939_tp": {
            "format": "TP Reassembled | {{data.summary}}"
        },
        "j1939_tp_fragment": {
            "format": "TP Fragment | {{data.summary}}"
        },
        "raw_can": {
            "format": "CAN 0x{{data.id}} [{{data.dlc}}]"
        },
        "error": {
            "format": "ERR: {{data.msg}}"
        },
    }

    def __init__(self):
        self._pending_id   = None
        self._pending_data = []
        self._pending_start = None
        self._tp_sessions  = {}  # keyed by source_address (int)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _sa_name(self, sa):
        return SA_NAMES.get(sa, f"SA 0x{sa:02X}")

    def _pgn_name(self, pgn):
        return PGN_NAMES.get(pgn, f"PGN 0x{pgn:04X}")

    def _decode_j1939_id(self, can_id):
        """Unpack 29-bit J1939 CAN ID → (priority, pgn, da, sa)"""
        priority = (can_id >> 26) & 0x07
        dp       = (can_id >> 24) & 0x01
        pf       = (can_id >> 16) & 0xFF
        ps       = (can_id >>  8) & 0xFF
        sa       = (can_id >>  0) & 0xFF

        if pf < 0xF0:
            # PDU1 — peer-to-peer: PS = destination address, PGN has PS=0
            da  = ps
            pgn = (dp << 17) | (pf << 8)
        else:
            # PDU2 — broadcast: PS is part of PGN
            da  = 0xFF  # Global
            pgn = (dp << 17) | (pf << 8) | ps

        return priority, pgn, da, sa

    def _build_frame(self, frame_type, start_time, end_time, data_dict):
        return AnalyzerFrame(frame_type, start_time, end_time, data_dict)

    def _process_complete_frame(self, can_id, data, start_time, end_time, is_extended):
        """Decode one complete CAN frame and return an AnalyzerFrame (or None)."""

        if not is_extended:
            # 11-bit standard frame — not J1939
            if self.show_standard_frames == "Show as Raw CAN":
                return self._build_frame("raw_can", start_time, end_time, {
                    "summary": f"STD 0x{can_id:03X} DLC={len(data)}",
                    "id":      f"{can_id:03X}",
                    "dlc":     str(len(data)),
                })
            return None

        priority, pgn, da, sa = self._decode_j1939_id(can_id)
        pgn_name = self._pgn_name(pgn)
        sa_name  = self._sa_name(sa)
        da_name  = self._sa_name(da) if da != 0xFF else "Broadcast"

        # ── Transport Protocol handling ───────────────────────────────────
        is_tp_cm = (pgn & 0x00FF00) == 0x00EC00
        is_tp_dt = (pgn & 0x00FF00) == 0x00EB00

        if is_tp_cm and len(data) == 8:
            ctrl = data[0]
            if ctrl == 0x20:  # BAM
                total_bytes  = data[1] | (data[2] << 8)
                num_packets  = data[3]
                tp_pgn       = data[5] | (data[6] << 8) | (data[7] << 16)
                self._tp_sessions[sa] = _TPSession(tp_pgn, total_bytes, num_packets, start_time)
                summary = (f"TP.BAM from {sa_name} → "
                           f"{self._pgn_name(tp_pgn)} "
                           f"({total_bytes}B in {num_packets} pkts)")
                if self.show_tp_fragments == "Show":
                    return self._build_frame("j1939_tp_fragment", start_time, end_time, {
                        "summary":  summary,
                        "from":     sa_name,
                        "pgn":      f"0x{tp_pgn:04X}",
                        "bytes":    str(total_bytes),
                        "packets":  str(num_packets),
                    })
                return None

        if is_tp_dt and len(data) == 8:
            seq     = data[0]
            payload = list(data[1:8])
            session = self._tp_sessions.get(sa)
            if session:
                session.add_packet(seq, payload)
                if session.is_complete():
                    reassembled = session.reassemble()
                    tp_pgn      = session.pgn
                    tp_pgn_name = self._pgn_name(tp_pgn)
                    decoder     = PGN_DECODERS.get(tp_pgn)
                    decoded     = decoder(reassembled) if decoder else None
                    if decoded:
                        summary = f"{tp_pgn_name} from {sa_name} | {decoded['decoded']}"
                    else:
                        hex_str = " ".join(f"{b:02X}" for b in reassembled)
                        summary = f"{tp_pgn_name} from {sa_name} | [{hex_str}]"
                    result = self._build_frame("j1939_tp", session.start_time, end_time, {
                        "summary": summary,
                        "pgn":     f"0x{tp_pgn:04X}",
                        "pgn_name": tp_pgn_name,
                        "from":    sa_name,
                        **(decoded or {}),
                    })
                    del self._tp_sessions[sa]
                    return result
                else:
                    if self.show_tp_fragments == "Show":
                        return self._build_frame("j1939_tp_fragment", start_time, end_time, {
                            "summary": f"TP.DT pkt#{seq} from {sa_name}",
                            "from":    sa_name,
                            "seq":     str(seq),
                        })
                    return None
            return None

        # ── Normal single-frame message ───────────────────────────────────
        decoder = PGN_DECODERS.get(pgn)
        decoded = decoder(data) if decoder else None

        if decoded:
            summary = f"{pgn_name} from {sa_name} | {decoded['decoded']}"
        else:
            hex_str = " ".join(f"{b:02X}" for b in data)
            summary = f"{pgn_name} from {sa_name} | [{hex_str}]"

        return self._build_frame("j1939", start_time, end_time, {
            "summary":  summary,
            "pgn":      f"0x{pgn:04X}",
            "pgn_name": pgn_name,
            "priority": str(priority),
            "from":     sa_name,
            "to":       da_name,
            **(decoded or {}),
        })

    # ── Main HLA entry point ──────────────────────────────────────────────────

    def decode(self, frame: AnalyzerFrame):
        """
        Called once per frame from the CAN low-level analyzer.

        The CAN LLA emits frames with these types:
          identifier_field  →  frame.data['identifier'] (int), frame.data.get('extended') (bool)
          data_field        →  frame.data['data'] (bytes, 1 byte per call)
          crc_field         →  frame.data['crc'] (int) — marks end of frame
          error_field       →  indicates a CAN error
        """
        ft = frame.type

        if ft == "identifier_field":
            # Start of a new CAN frame — reset accumulator
            self._pending_id    = frame.data.get("identifier")
            self._pending_data  = []
            self._pending_start = frame.start_time
            self._pending_ext   = bool(frame.data.get("extended", False))
            return None

        elif ft == "data_field":
            raw = frame.data.get("data")
            if raw is not None:
                # data field delivers a bytes object, one byte per frame
                if isinstance(raw, bytes):
                    self._pending_data.extend(raw)
                else:
                    self._pending_data.append(int(raw))
            return None

        elif ft == "crc_field":
            # Frame complete — decode it
            if self._pending_id is None:
                return None
            result = self._process_complete_frame(
                can_id      = self._pending_id,
                data        = self._pending_data,
                start_time  = self._pending_start,
                end_time    = frame.end_time,
                is_extended = self._pending_ext,
            )
            self._pending_id   = None
            self._pending_data = []
            return result

        elif ft == "error_field":
            return self._build_frame("error", frame.start_time, frame.end_time, {
                "summary": "CAN error frame",
                "msg":     "CAN bus error",
            })

        return None
