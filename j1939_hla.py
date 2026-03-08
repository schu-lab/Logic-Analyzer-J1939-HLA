# =============================================================================
# J1939 High-Level Analyzer for Saleae Logic 2
# =============================================================================
# Sits on top of Logic 2's built-in CAN low-level analyzer.
# Decodes J1939 extended (29-bit) frames:
#   - Priority, PGN, Destination Address, Source Address
#   - Human-readable PGN names
#   - Signal-level decoding for many standard PGNs
#   - Transport Protocol BAM reassembly (multi-packet messages)
#
# Installation:
#   1. In Logic 2, open the Extensions panel (right sidebar)
#   2. Click "+" -> "Load Existing Extension"
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
    # ---------------------------------------------------------------------------
    # J1939-71 additions
    # ---------------------------------------------------------------------------
    0x00FEE9: "Fuel Consumption (Liquid) (LFC)",
    0x00FEE0: "Vehicle Distance (VD)",
    0x00FEE3: "Software Identification (SOFT)",
    0x00FEE4: "ECU History (ECUH)",
    0x00FEE5: "Time/Date (TD)",
    0x00FEE6: "Vehicle Hours 2 (VH2)",
    0x00FEEA: "Torque/Speed Control 1 (TSC1)",
    0x00FEB0: "Transmission Fluids 2 (TF2)",
    0x00FEB4: "Engine Fluid Level/Pressure 2 (EFL/P2)",
    0x00FEB5: "Fuel Economy (Gaseous) (GFE)",
    0x00FEB6: "Average Fuel Economy (Gaseous) (AGFE)",
    0x00FEBD: "Engine Temperature 2 (ET2)",
    0x00FEC0: "Fuel Consumption (Gaseous) 2 (GFC2)",
    0x00FEC1: "High Resolution Vehicle Distance (HRVD)",
    0x00FEC2: "High Resolution Engine Total Fuel Used (HRETF)",
    0x00FEC3: "Electronic Steering Controller (ESC)",
    0x00FEA8: "Electronic Engine Controller 7 (EEC7)",
    0x00FEA9: "Engine Torque History (ETH)",
    0x00FE56: "Operator Seat Direction Switch (OSD)",
    0x00FE6E: "Air Suspension Control 1 (ASC1)",
    0x00FE6F: "Air Suspension Control 2 (ASC2)",
    0x00FEBC: "Hydraulic Pressure (HP)",
    0x00FEBE: "Forward Road Image Processing (FRIP)",
    0x00FEC4: "Engine Hours (EH2)",
    0x00FEC5: "Electronic Transmission Controller 3 (ETC3)",
    0x00FEC6: "Electronic Transmission Controller 4 (ETC4)",
    0x00FEC7: "Electronic Transmission Controller 5 (ETC5)",
    0x00FEC8: "Electronic Transmission Controller 6 (ETC6)",
    0x00FEC9: "Electronic Transmission Controller 7 (ETC7)",
    # ---------------------------------------------------------------------------
    # J1939-73 DM message additions
    # ---------------------------------------------------------------------------
    0x00FECD: "Freeze Frame Parameters (DM4)",
    0x00FED2: "Emission-Related Permanent DTCs (DM9)",
    0x00FED3: "Emission-Related Pending DTCs 2 (DM10)",
    0x00FED4: "Emission Diag Data Clear (DM11)",
    0x00FED5: "Emission-Related Active DTCs (DM12)",
    0x00FED6: "Stop Start Broadcast (DM13)",
    0x00FED7: "Memory Access Request (DM14)",
    0x00FED9: "Memory Access Response (DM15)",
    0x00FEDA: "Binary Data Transfer (DM16)",
    0x00FEDC: "Individual DTC Clear/Reset (DM22)",
    0x00FEDD: "Emission-Related Previously Active DTCs (DM23)",
    0x00FEDE: "SPN Support (DM24)",
    0x00FEDF: "Expanded Freeze Frame (DM25)",
    0x00FEE1: "All Pending DTCs (DM27)",
    0x00FEE2: "Permanent DTCs (DM28)",
    0x00D300: "Regulated Exhaust Emission Levels (DM29)",
    0x00D400: "Scaled Test Results (DM30)",
    0x00D500: "DTC to Lamp Association (DM31)",
    0x00D600: "Exhaust Emission Exceedance (DM32)",
    0x00D700: "Emission Increasing AECD Active Time (DM33)",
    0x00D800: "NTE Status (DM34)",
    0x00D900: "Immediate Fault Status (DM35)",
    0x00DA00: "DTC Counts (DM36)",
    0x00DB00: "DM17 - Boot Load Data",
    0x00DC00: "DM18 - Data Security",
    0x00DD00: "DM19 - Calibration Information",
    0x00DE00: "DM20 - Monitor Performance Ratio",
    0x00DF00: "DM26 - Diagnostic Readiness 3",
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
# Gear names for transmission decoding
# ---------------------------------------------------------------------------
GEAR_NAMES = {
    0xFB: "Park",
    0xFC: "Reverse",
    0xFD: "Neutral",
    0xFE: "N/A",
    0xFF: "N/A",
}

# ---------------------------------------------------------------------------
# Common helper functions
# ---------------------------------------------------------------------------

def _na(val, sentinel=0xFF):
    return val == sentinel

def _na16(val, sentinel=0xFFFF):
    return val == sentinel

def _lamp(bits2):
    """Decode 2-bit lamp state per J1939-73."""
    return {0b00: "OFF", 0b01: "ON", 0b10: "Special", 0b11: "N/A"}.get(bits2, "?")

def _spn_2bit(bits2):
    """Generic 2-bit SPN state: 00=Off, 01=On, 10=Error, 11=N/A."""
    return {0b00: "Off", 0b01: "On", 0b10: "Error", 0b11: "N/A"}.get(bits2, "?")

def _temp_c(raw, offset=40):
    """1-byte temperature with offset, returns string."""
    if raw == 0xFF:
        return "N/A"
    return f"{raw - offset}degC"

def _temp16_c(raw, scale=0.03125, offset=273.0):
    """2-byte temperature (K scale -> degC), e.g. for EEC2 charge air."""
    if raw == 0xFFFF:
        return "N/A"
    return f"{raw * scale - offset:.1f}degC"

def _pct(raw, offset=125):
    """1-byte percent with 125 offset (torque, etc.)."""
    if raw == 0xFF:
        return "N/A"
    return f"{raw - offset}%"

def _pct_raw(raw, scale=0.4):
    """1-byte 0-100% with scale factor."""
    if raw == 0xFF:
        return "N/A"
    return f"{raw * scale:.1f}%"

def _press_kpa(raw, scale=0.5):
    """1-byte pressure in kPa."""
    if raw == 0xFF:
        return "N/A"
    return f"{raw * scale:.1f} kPa"

def _press16_kpa(raw, scale=0.1):
    """2-byte pressure in kPa."""
    if raw == 0xFFFF:
        return "N/A"
    return f"{raw * scale:.1f} kPa"

def _voltage(raw, scale=0.05):
    """2-byte voltage."""
    if raw == 0xFFFF:
        return "N/A"
    return f"{raw * scale:.2f} V"

def _gear(raw):
    """Decode gear number (signed with special values)."""
    if raw in GEAR_NAMES:
        return GEAR_NAMES[raw]
    if raw <= 250:
        return f"Gear {raw}"
    return f"0x{raw:02X}"

def _rpm(raw, scale=0.125):
    """2-byte engine speed."""
    if raw == 0xFFFF:
        return "N/A"
    return f"{raw * scale:.1f} RPM"

def _speed_kmh(raw, scale=1.0/256.0):
    """2-byte wheel speed in km/h."""
    if raw == 0xFFFF:
        return "N/A"
    return f"{raw * scale:.2f} km/h"

def _ratio(raw, scale=0.001):
    """2-byte ratio (e.g. torque converter)."""
    if raw == 0xFFFF:
        return "N/A"
    return f"{raw * scale:.3f}"

def _flow_lph(raw, scale=0.05):
    """2-byte fuel flow in L/h."""
    if raw == 0xFFFF:
        return "N/A"
    return f"{raw * scale:.2f} L/h"

def _distance_km(raw, scale=0.125):
    """4-byte distance in km."""
    if raw == 0xFFFFFFFF:
        return "N/A"
    return f"{raw * scale:.1f} km"

def _hours(raw, scale=0.05):
    """4-byte hours."""
    if raw == 0xFFFFFFFF:
        return "N/A"
    return f"{raw * scale:.2f} h"

def _angle_deg(raw, scale=0.0078125, offset=0):
    """2-byte angle in degrees."""
    if raw == 0xFFFF:
        return "N/A"
    return f"{raw * scale - offset:.2f}deg"


# ---------------------------------------------------------------------------
# PGN signal decoders
# ---------------------------------------------------------------------------

def decode_eec1(data):
    """PGN 0xF004 - Electronic Engine Controller 1
    Byte 0: Engine Torque Mode (nibbles)
    Byte 1: Driver's Demand Engine - Percent Torque
    Byte 2: Actual Engine - Percent Torque
    Bytes 3-4: Engine Speed (0.125 RPM/bit)
    Byte 5: Source Address of Controlling Device
    Byte 6: Engine Starter Mode (nibbles)
    Byte 7: Engine Demand - Percent Torque
    """
    if len(data) < 8:
        return None

    torque_mode_raw = data[0] & 0x0F
    torque_mode_names = {
        0: "Low Idle Governor",
        1: "Accelerator Pedal",
        2: "Cruise Control",
        3: "PTO Governor",
        4: "Road Speed Governor",
        5: "ASR Control",
        6: "Transmission Control",
        7: "ABS Control",
        8: "Torque Limiting",
        9: "High Speed Governor",
        10: "Braking System",
        11: "Remote Accelerator",
        12: "Service Procedure",
        13: "Not Defined",
        14: "Other",
        15: "N/A",
    }
    torque_mode = torque_mode_names.get(torque_mode_raw, f"Mode {torque_mode_raw}")

    driver_demand = _pct(data[1])
    actual_torque = _pct(data[2])
    speed_raw     = data[3] | (data[4] << 8)
    speed_str     = _rpm(speed_raw)
    src_ctrl      = SA_NAMES.get(data[5], f"0x{data[5]:02X}")
    demand_torque = _pct(data[7]) if len(data) > 7 else "N/A"

    starter_raw = (data[6] >> 4) & 0x0F
    starter_names = {0: "Off", 1: "Start Not Active", 2: "Starter Active Gear Not Engaged",
                     3: "Starter Active Gear Engaged", 4: "Start Finished", 12: "Error",
                     14: "Other", 15: "N/A"}
    starter = starter_names.get(starter_raw, f"Mode {starter_raw}")

    return {
        "decoded":       f"Speed={speed_str}  Torque={actual_torque}  Demand={driver_demand}  Mode={torque_mode}",
        "speed_rpm":     speed_str,
        "actual_torque": actual_torque,
        "driver_demand": driver_demand,
        "eng_demand":    demand_torque,
        "torque_mode":   torque_mode,
        "starter_mode":  starter,
        "ctrl_src_addr": src_ctrl,
    }


def decode_eec2(data):
    """PGN 0xF005 - Electronic Engine Controller 2
    Byte 0: Accelerator Pedal Position (0.4%/bit)
    Byte 1: Engine Percent Load At Current Speed (1%/bit)
    Byte 2: Remote Accelerator Pedal Position (0.4%/bit)
    Byte 3: Accelerator Pedal Low Idle Switch / Kickdown
    Byte 4: Engine Maximum Momentary Overspeed Enable
    Byte 5-6: Estimated Pumping Percent Torque (10 bit), Engine Load  
    """
    if len(data) < 8:
        return None

    accel     = _pct_raw(data[0], 0.4)
    load      = f"{data[1]}%" if data[1] != 0xFF else "N/A"
    remote    = _pct_raw(data[2], 0.4)

    low_idle  = _spn_2bit(data[3] & 0x03)
    kickdown  = _spn_2bit((data[3] >> 2) & 0x03)
    road_spd  = _spn_2bit((data[3] >> 4) & 0x03)

    return {
        "decoded":      f"Accel={accel}  Load={load}  Remote={remote}  LowIdle={low_idle}",
        "accel_pos":    accel,
        "engine_load":  load,
        "remote_accel": remote,
        "low_idle_sw":  low_idle,
        "kickdown":     kickdown,
        "road_spd_lmt": road_spd,
    }


def decode_eec3(data):
    """PGN 0xF006 - Electronic Engine Controller 3
    Byte 0: Nominal Friction - Percent Torque
    Byte 1-2: Engine's Desired Operating Speed (0.125 RPM/bit)
    Byte 3: Engine's Desired Operating Speed Asymmetry Adjustment
    Byte 4: Estimated Engine Parasitic Losses - Percent Torque
    Bytes 5-7: Aftertreatment 1 & 2 Exhaust Gas Mass Flow Rate
    """
    if len(data) < 8:
        return None

    friction  = _pct(data[0])
    des_speed = _rpm(data[1] | (data[2] << 8))
    parasitic = _pct(data[4])

    return {
        "decoded":         f"DesiredSpeed={des_speed}  NomFriction={friction}  Parasitic={parasitic}",
        "desired_speed":   des_speed,
        "nom_friction":    friction,
        "parasitic_loss":  parasitic,
    }


def decode_etc1(data):
    """PGN 0xF007 - Electronic Transmission Controller 1
    Byte 0: bits 0-1 Transmission Driveline Engaged
            bits 2-3 Torque Converter Lockup Engaged
            bits 4-5 Shift In Progress
    Byte 1-2: Transmission Output Shaft Speed (0.125 RPM/bit)
    Byte 3: Percent Clutch Slip (0.4%/bit)
    Byte 4: bits 0-1 Engine Momentary Overspeed Enable
            bits 2-3 Progressive Shift Disable
    Byte 5-6: Transmission Input Shaft Speed (0.125 RPM/bit)
    Byte 7: Source Address of Controlling Device
    """
    if len(data) < 8:
        return None

    driveline = _spn_2bit(data[0] & 0x03)
    tc_lockup  = _spn_2bit((data[0] >> 2) & 0x03)
    shift_prog = _spn_2bit((data[0] >> 4) & 0x03)
    output_spd = _rpm(data[1] | (data[2] << 8))
    clutch_slp = _pct_raw(data[3], 0.4)
    input_spd  = _rpm(data[5] | (data[6] << 8))

    return {
        "decoded":        f"OutputSpd={output_spd}  InputSpd={input_spd}  TCLockup={tc_lockup}  Shift={shift_prog}",
        "output_shaft_spd": output_spd,
        "input_shaft_spd":  input_spd,
        "driveline":        driveline,
        "tc_lockup":        tc_lockup,
        "shift_in_prog":    shift_prog,
        "clutch_slip":      clutch_slp,
    }


def decode_etc2(data):
    """PGN 0xF008 - Electronic Transmission Controller 2
    Byte 0: Transmission Selected Gear
    Byte 1-2: Transmission Actual Gear Ratio (0.001/bit)
    Byte 3: Transmission Current Gear
    Byte 4-5: Transmission Requested Range (ASCII 2 chars)
    Byte 6-7: Transmission Current Range (ASCII 2 chars)
    """
    if len(data) < 8:
        return None

    sel_gear  = _gear(data[0])
    ratio_raw = data[1] | (data[2] << 8)
    ratio     = _ratio(ratio_raw)
    cur_gear  = _gear(data[3])

    try:
        req_range = "".join(chr(b) for b in data[4:6] if 0x20 <= b <= 0x7E).strip() or "N/A"
        cur_range = "".join(chr(b) for b in data[6:8] if 0x20 <= b <= 0x7E).strip() or "N/A"
    except Exception:
        req_range = "N/A"
        cur_range = "N/A"

    return {
        "decoded":       f"CurGear={cur_gear}  SelGear={sel_gear}  Ratio={ratio}  CurRange={cur_range}",
        "current_gear":  cur_gear,
        "selected_gear": sel_gear,
        "gear_ratio":    ratio,
        "req_range":     req_range,
        "cur_range":     cur_range,
    }


def decode_erc1(data):
    """PGN 0xF00B - Electronic Retarder Controller 1
    Byte 0: bits 0-1 Retarder Enable/Brake Assist Switch
            bits 2-3 Retarder Remote/Exhaust Brake Enable
            bits 4-5 Retarder Selection (Non-Engine)
            bits 6-7 ASC Retarder Lamp
    Byte 1: Actual Retarder - Percent Torque
    Byte 2: Intended Retarder - Percent Torque
    Byte 3: Coolant Load Increase
    Byte 4: Source Address of Controlling Device
    Byte 5: Engine Coolant Load Increase
    Byte 6: Retarder Requesting Brake Light
    """
    if len(data) < 8:
        return None

    enable      = _spn_2bit(data[0] & 0x03)
    remote_en   = _spn_2bit((data[0] >> 2) & 0x03)
    actual_trq  = _pct(data[1])
    intended_trq = _pct(data[2])
    coolant_load = _spn_2bit(data[3] & 0x03)

    return {
        "decoded":        f"ActualTorque={actual_trq}  IntendedTorque={intended_trq}  Enable={enable}",
        "actual_torque":  actual_trq,
        "intended_torque": intended_trq,
        "enable_switch":  enable,
        "remote_enable":  remote_en,
        "coolant_load":   coolant_load,
    }


def decode_ebc1(data):
    """PGN 0xF002 - Electronic Brake Controller 1
    Byte 0: ASR Engine Control Active / ASR Brake Control Active / ABS Active
    Byte 1: ASR Engine Control Active / Remote Accelerator Enable Switch
    Byte 2: Source Address of Controlling Device
    Byte 3: Brake Pedal Position (0.4%/bit)
    Byte 4: ABS Off-road Switch / ASR Off-road Switch / ASR Hill Holder Switch
    Byte 5: Traction Control Override Switch / Accelerator Interlock Switch
    Byte 6: Engine Derate Switch / Auxiliary Engine Shutdown Switch
    Byte 7: Remote Accelerator Enable Switch
    """
    if len(data) < 8:
        return None

    abs_active  = _spn_2bit((data[0] >> 2) & 0x03)
    asr_eng     = _spn_2bit(data[0] & 0x03)
    asr_brake   = _spn_2bit((data[0] >> 4) & 0x03)
    brake_pos   = _pct_raw(data[3], 0.4)
    abs_offroad = _spn_2bit(data[4] & 0x03)

    return {
        "decoded":       f"BrakePedal={brake_pos}  ABS={abs_active}  ASREngine={asr_eng}  ASRBrake={asr_brake}",
        "brake_pedal":   brake_pos,
        "abs_active":    abs_active,
        "asr_engine":    asr_eng,
        "asr_brake":     asr_brake,
        "abs_offroad":   abs_offroad,
    }


def decode_ccvs(data):
    """PGN 0xFEF1 - Cruise Control / Vehicle Speed
    Byte 0: Cruise Control related switches (8 x 2-bit SPNs)
    Byte 1-2: Wheel-Based Vehicle Speed (1/256 km/h per bit)
    Byte 3: Cruise Control Set Speed (1 km/h per bit)
    Byte 4: PTO Governor State / Cruise Control States
    Byte 5: Idle Increment Switch / Idle Decrement Switch
    Byte 6: Engine Test Mode Switch / Engine Shutdown Override Switch
    Byte 7: Cruise Control High Set Limit Speed / Low Set Limit Speed
    """
    if len(data) < 8:
        return None

    speed_raw   = data[1] | (data[2] << 8)
    speed_str   = _speed_kmh(speed_raw)
    cc_set_spd  = f"{data[3]} km/h" if data[3] != 0xFF else "N/A"

    cc_active   = _spn_2bit(data[0] & 0x03)
    cc_enable   = _spn_2bit((data[0] >> 2) & 0x03)
    brake_sw    = _spn_2bit((data[0] >> 4) & 0x03)
    clutch_sw   = _spn_2bit((data[0] >> 6) & 0x03)
    cc_set_sw   = _spn_2bit(data[4] & 0x03)
    cc_coast_sw = _spn_2bit((data[4] >> 2) & 0x03)
    cc_resume   = _spn_2bit((data[4] >> 4) & 0x03)
    cc_accel    = _spn_2bit((data[4] >> 6) & 0x03)

    pto_state_raw = (data[4] >> 4) & 0x0F
    pto_states = {0: "Off/Disabled", 1: "Hold", 2: "Remote Hold", 3: "Standby",
                  4: "Remote Standby", 5: "Set", 6: "Decel", 7: "Resume",
                  8: "Accel", 9: "Accel Decel", 10: "PTO Active", 11: "Remote PTO Active",
                  14: "Error", 15: "N/A"}

    return {
        "decoded":      f"Speed={speed_str}  CC Active={cc_active}  SetSpd={cc_set_spd}  Brake={brake_sw}",
        "speed_km_h":   speed_str,
        "cc_active":    cc_active,
        "cc_enable":    cc_enable,
        "cc_set_speed": cc_set_spd,
        "cc_set_sw":    cc_set_sw,
        "cc_coast_sw":  cc_coast_sw,
        "cc_resume":    cc_resume,
        "cc_accel":     cc_accel,
        "brake_sw":     brake_sw,
        "clutch_sw":    clutch_sw,
    }


def decode_et1(data):
    """PGN 0xFEEF - Engine Temperature 1
    Byte 0: Engine Coolant Temperature (offset -40degC)
    Byte 1: Engine Fuel Temperature 1 (offset -40degC)
    Bytes 2-3: Engine Oil Temperature 1 (0.03125 K/bit, offset -273degC)
    Bytes 4-5: Engine Turbo Oil Temperature (0.03125 K/bit, offset -273degC)
    Byte 6: Engine Coolant Temperature (High Resolution) (offset -40degC)
    Byte 7: Engine Intercooler Temperature (offset -40degC)
    """
    if len(data) < 8:
        return None

    coolant    = _temp_c(data[0])
    fuel       = _temp_c(data[1])
    oil_raw    = data[2] | (data[3] << 8)
    oil        = _temp16_c(oil_raw)
    turbo_raw  = data[4] | (data[5] << 8)
    turbo_oil  = _temp16_c(turbo_raw)
    intercooler = _temp_c(data[7])

    return {
        "decoded":         f"Coolant={coolant}  Oil={oil}  Fuel={fuel}  Intercooler={intercooler}",
        "coolant_temp":    coolant,
        "oil_temp":        oil,
        "fuel_temp":       fuel,
        "turbo_oil_temp":  turbo_oil,
        "intercooler_temp": intercooler,
    }


def decode_tf(data):
    """PGN 0xFEF0 - Transmission Fluids 1
    Byte 0: Transmission Clutch 1 Pressure (1.6 kPa/bit)
    Byte 1: Transmission Clutch 2 Pressure (1.6 kPa/bit)
    Bytes 2-3: Transmission Oil Temperature (0.03125 K/bit, offset -273degC)
    Byte 4: Transmission Oil Level (0.4%/bit)
    Byte 5: Transmission Oil Level High/Low
    Byte 6: Transmission Filter Differential Pressure (0.5 kPa/bit)
    Byte 7: Transmission Torque Converter Differential Pressure (0.5 kPa/bit)
    """
    if len(data) < 8:
        return None

    cl1_press = f"{data[0] * 1.6:.1f} kPa" if data[0] != 0xFF else "N/A"
    cl2_press = f"{data[1] * 1.6:.1f} kPa" if data[1] != 0xFF else "N/A"
    oil_raw   = data[2] | (data[3] << 8)
    oil_temp  = _temp16_c(oil_raw)
    oil_level = _pct_raw(data[4], 0.4)
    filt_dp   = _press_kpa(data[6])
    tc_dp     = _press_kpa(data[7])

    lvl_status_raw = data[5] & 0x0F
    lvl_status_names = {0: "Low -3", 1: "Low -2", 2: "Low -1", 3: "Low", 4: "Nominal",
                        5: "High", 6: "High +1", 7: "High +2", 8: "Error",
                        14: "Not available", 15: "N/A"}
    lvl_status = lvl_status_names.get(lvl_status_raw, f"Lvl {lvl_status_raw}")

    return {
        "decoded":       f"OilTemp={oil_temp}  Level={oil_level}({lvl_status})  Cl1={cl1_press}  Cl2={cl2_press}",
        "trans_oil_temp":  oil_temp,
        "trans_oil_level": oil_level,
        "lvl_status":      lvl_status,
        "clutch1_press":   cl1_press,
        "clutch2_press":   cl2_press,
        "filter_dp":       filt_dp,
        "tc_dp":           tc_dp,
    }


def decode_lfe(data):
    """PGN 0xFEF2 - Fuel Economy (Liquid)
    Bytes 0-1: Engine Fuel Rate (0.05 L/h per bit)
    Bytes 2-3: Engine Instantaneous Fuel Economy (1/512 km/L per bit)
    Bytes 4-5: Engine Average Fuel Economy (1/512 km/L per bit)
    Bytes 6-7: Engine Throttle Valve 1 Position (0.4%/bit)
    """
    if len(data) < 8:
        return None

    rate_raw = data[0] | (data[1] << 8)
    fuel_rate = _flow_lph(rate_raw)

    inst_raw = data[2] | (data[3] << 8)
    inst_eco = f"{inst_raw / 512.0:.3f} km/L" if inst_raw != 0xFFFF else "N/A"

    avg_raw = data[4] | (data[5] << 8)
    avg_eco = f"{avg_raw / 512.0:.3f} km/L" if avg_raw != 0xFFFF else "N/A"

    throttle = _pct_raw(data[6], 0.4)

    return {
        "decoded":        f"FuelRate={fuel_rate}  InstEco={inst_eco}  AvgEco={avg_eco}  Throttle={throttle}",
        "fuel_rate_lph":  fuel_rate,
        "inst_fuel_eco":  inst_eco,
        "avg_fuel_eco":   avg_eco,
        "throttle_pos":   throttle,
    }


def decode_amb(data):
    """PGN 0xFEF3 - Ambient Conditions
    Byte 0: Barometric Pressure (0.5 kPa/bit)
    Byte 1: Cab Interior Temperature (offset -40degC)
    Byte 2: Ambient Air Temperature (offset -40degC)
    Bytes 3-4: Air Inlet Temperature (0.03125 K/bit, offset -273degC)
    Byte 5: Road Surface Temperature (offset -40degC)
    Bytes 6-7: Air Inlet Pressure (0.1 kPa/bit, 2-byte)
    """
    if len(data) < 8:
        return None

    baro      = _press_kpa(data[0])
    cab_temp  = _temp_c(data[1])
    amb_temp  = _temp_c(data[2])
    inlet_raw = data[3] | (data[4] << 8)
    inlet_temp = _temp16_c(inlet_raw)
    road_temp = _temp_c(data[5])
    inlet_prs = _press16_kpa(data[6] | (data[7] << 8), scale=0.1)

    return {
        "decoded":       f"AmbTemp={amb_temp}  Baro={baro}  CabTemp={cab_temp}  InletTemp={inlet_temp}",
        "ambient_temp":  amb_temp,
        "cab_temp":      cab_temp,
        "baro_press":    baro,
        "air_inlet_temp": inlet_temp,
        "air_inlet_press": inlet_prs,
        "road_temp":     road_temp,
    }


def decode_ic1(data):
    """PGN 0xFEF4 - Intake/Exhaust Conditions 1
    Byte 0: Particulate Trap Inlet Pressure (0.5 kPa/bit)
    Byte 1: Boost Pressure (2 kPa/bit)
    Byte 2: Intake Manifold 1 Temperature (offset -40degC)
    Bytes 3-4: Air Inlet Pressure (0.1 kPa/bit, 2-byte)
    Byte 5: Air Filter 1 Differential Pressure (0.05 kPa/bit)
    Bytes 6-7: Exhaust Gas Temperature (0.03125 K/bit, offset -273degC)
    """
    if len(data) < 8:
        return None

    trap_press   = _press_kpa(data[0])
    boost_press  = f"{data[1] * 2:.0f} kPa" if data[1] != 0xFF else "N/A"
    manifold_tmp = _temp_c(data[2])
    inlet_prs    = _press16_kpa(data[3] | (data[4] << 8), scale=0.1)
    filter_dp    = f"{data[5] * 0.05:.3f} kPa" if data[5] != 0xFF else "N/A"
    exh_raw      = data[6] | (data[7] << 8)
    exh_temp     = _temp16_c(exh_raw)

    return {
        "decoded":         f"Boost={boost_press}  ManifoldTemp={manifold_tmp}  ExhaustTemp={exh_temp}  InletP={inlet_prs}",
        "boost_press":     boost_press,
        "manifold_temp":   manifold_tmp,
        "exhaust_temp":    exh_temp,
        "inlet_press":     inlet_prs,
        "trap_inlet_press": trap_press,
        "filter_dp":       filter_dp,
    }


def decode_vep1(data):
    """PGN 0xFEF5 - Vehicle Electrical Power 1
    Bytes 0-1: Net Battery Current (1A/bit, offset -125A)
    Bytes 2-3: Alternator Current (1A/bit)
    Bytes 4-5: Charging Voltage (0.05V/bit)
    Bytes 6-7: Battery Potential / Power Input 1 (0.05V/bit)
    """
    if len(data) < 8:
        return None

    batt_curr_raw = data[0] | (data[1] << 8)
    batt_curr = f"{batt_curr_raw - 125} A" if batt_curr_raw != 0xFFFF else "N/A"

    alt_curr_raw = data[2] | (data[3] << 8)
    alt_curr = f"{alt_curr_raw} A" if alt_curr_raw != 0xFFFF else "N/A"

    chg_volt = _voltage(data[4] | (data[5] << 8))
    batt_volt = _voltage(data[6] | (data[7] << 8))

    return {
        "decoded":        f"BattVolt={batt_volt}  ChgVolt={chg_volt}  BattCurr={batt_curr}  AltCurr={alt_curr}",
        "battery_volt":   batt_volt,
        "charging_volt":  chg_volt,
        "battery_curr":   batt_curr,
        "alternator_curr": alt_curr,
    }


def decode_eflp1(data):
    """PGN 0xFEF7 - Engine Fluid Level/Pressure 1
    Byte 0: Engine Fuel Delivery Pressure (4 kPa/bit)
    Byte 1: Engine Extended Crankcase Blow-by Pressure (0.05 kPa/bit)
    Byte 2: Engine Oil Level (0.4%/bit)
    Byte 3: Engine Oil Pressure (4 kPa/bit)
    Bytes 4-5: Engine Coolant Pressure (0.1 kPa/bit)
    Byte 6: Engine Coolant Level (0.4%/bit)
    """
    if len(data) < 8:
        return None

    fuel_del_p  = f"{data[0] * 4} kPa" if data[0] != 0xFF else "N/A"
    blowby_p    = f"{data[1] * 0.05:.2f} kPa" if data[1] != 0xFF else "N/A"
    oil_level   = _pct_raw(data[2], 0.4)
    oil_press   = f"{data[3] * 4} kPa" if data[3] != 0xFF else "N/A"
    cool_p_raw  = data[4] | (data[5] << 8)
    cool_press  = _press16_kpa(cool_p_raw, scale=0.1)
    cool_level  = _pct_raw(data[6], 0.4)

    return {
        "decoded":          f"OilPress={oil_press}  OilLevel={oil_level}  CoolantPress={cool_press}  CoolantLevel={cool_level}",
        "oil_pressure":     oil_press,
        "oil_level":        oil_level,
        "coolant_pressure": cool_press,
        "coolant_level":    cool_level,
        "fuel_del_press":   fuel_del_p,
        "crankcase_press":  blowby_p,
    }


def decode_hours(data):
    """PGN 0xFEEB - Engine Hours / Revolutions
    Bytes 0-3: Total Engine Hours (0.05 h/bit)
    Bytes 4-7: Total Engine Revolutions (1000 rev/bit)
    """
    if len(data) < 8:
        return None

    hrs_raw = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    hours   = _hours(hrs_raw)

    rev_raw = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
    revs    = f"{rev_raw * 1000:,} rev" if rev_raw != 0xFFFFFFFF else "N/A"

    return {
        "decoded":       f"Hours={hours}  Revolutions={revs}",
        "engine_hours":  hours,
        "engine_revs":   revs,
    }


def decode_vd(data):
    """PGN 0xFEE0 - Vehicle Distance
    Bytes 0-3: Trip Distance (0.125 km/bit)
    Bytes 4-7: Total Vehicle Distance (0.125 km/bit)
    """
    if len(data) < 8:
        return None

    trip_raw  = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    total_raw = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
    trip  = _distance_km(trip_raw)
    total = _distance_km(total_raw)

    return {
        "decoded":      f"TripDist={trip}  TotalDist={total}",
        "trip_dist":    trip,
        "total_dist":   total,
    }


def decode_fd(data):
    """PGN 0xFEFC (actually FEFC is CI; FD = Fuel Consumption - use FEFC slot)
    PGN 0xFEF4 already taken -> this is for 0xFEE9 (Fuel Consumption - Liquid)
    Bytes 0-3: Trip Fuel (0.5 L/bit)
    Bytes 4-7: Total Fuel Used (0.5 L/bit)
    """
    if len(data) < 8:
        return None

    trip_raw  = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    total_raw = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)

    trip  = f"{trip_raw * 0.5:.1f} L" if trip_raw != 0xFFFFFFFF else "N/A"
    total = f"{total_raw * 0.5:.1f} L" if total_raw != 0xFFFFFFFF else "N/A"

    return {
        "decoded":       f"TripFuel={trip}  TotalFuel={total}",
        "trip_fuel":     trip,
        "total_fuel":    total,
    }


def decode_wfi(data):
    """PGN 0xFEFE - Water in Fuel Indicator
    Byte 0: bits 0-1 Water In Fuel Indicator
            bits 2-3 Fuel Filter Differential Pressure (prelim)
            bits 4-5 Fuel Filter Differential Pressure (final)
    """
    if len(data) < 1:
        return None

    wif     = _spn_2bit(data[0] & 0x03)
    pre_dp  = _spn_2bit((data[0] >> 2) & 0x03)
    fin_dp  = _spn_2bit((data[0] >> 4) & 0x03)

    return {
        "decoded":       f"WaterInFuel={wif}  PreFilterDP={pre_dp}  FinalFilterDP={fin_dp}",
        "water_in_fuel": wif,
        "pre_filter_dp": pre_dp,
        "fin_filter_dp": fin_dp,
    }


def decode_ac(data):
    """PGN 0xEE00 - Address Claim / Cannot Claim
    64-bit NAME field per J1939-81:
    Bits 63:   Self-Configurable Address
    Bits 62-60: Industry Group
    Bits 59-56: Vehicle System Instance
    Bits 55-49: Vehicle System
    Bits 48:   Reserved
    Bits 47-42: Function
    Bits 41-40: Function Instance
    Bits 39-35: ECU Instance
    Bits 34-21: Manufacturer Code (11 bits)
    Bits 20-0:  Identity Number (21 bits)
    """
    if len(data) < 8:
        return None

    identity = data[0] | (data[1] << 8) | ((data[2] & 0x1F) << 16)
    mfr_code = ((data[2] >> 5) & 0x07) | ((data[3] & 0xFF) << 3)
    ecu_inst = (data[4] & 0x07)
    fn_inst  = (data[4] >> 3) & 0x1F
    function = data[5]
    vs       = (data[6] >> 1) & 0x7F
    vs_inst  = data[7] & 0x0F                              # bits 3-0 of byte 7 per J1939-81
    ind_grp  = (data[7] >> 4) & 0x07
    self_cfg = (data[7] >> 7) & 0x01

    ind_grp_names = {0: "Global", 1: "On-Highway", 2: "Agricultural", 3: "Construction",
                     4: "Marine", 5: "Industrial"}

    return {
        "decoded":       f"NAME: MfrCode={mfr_code} Fn={function} VS={vs} IndGrp={ind_grp_names.get(ind_grp, str(ind_grp))} ID={identity}",
        "identity_num":  str(identity),
        "mfr_code":      str(mfr_code),
        "function":      str(function),
        "fn_instance":   str(fn_inst),
        "ecu_instance":  str(ecu_inst),
        "vehicle_sys":   str(vs),
        "vs_instance":   str(vs_inst),
        "industry_grp":  ind_grp_names.get(ind_grp, str(ind_grp)),
        "self_cfg_addr": "Yes" if self_cfg else "No",
    }


def decode_request(data):
    """PGN 0xEA00 - Request PGN
    Bytes 0-2: Requested PGN
    """
    if len(data) < 3:
        return None

    req_pgn = data[0] | (data[1] << 8) | (data[2] << 16)
    req_name = PGN_NAMES.get(req_pgn, f"PGN 0x{req_pgn:04X}")

    return {
        "decoded":       f"Request for {req_name}",
        "requested_pgn": f"0x{req_pgn:04X}",
        "pgn_name":      req_name,
    }


def decode_ack(data):
    """PGN 0xE800 - Acknowledgement
    Byte 0: Control byte (0=ACK, 1=NACK, 2=Access Denied, 3=Cannot Respond)
    Byte 1: Group function value
    Bytes 2-4: reserved
    Bytes 5-7: PGN being acknowledged
    """
    if len(data) < 8:
        return None

    ctrl_names = {0: "ACK", 1: "NACK", 2: "Access Denied", 3: "Cannot Respond"}
    ctrl = ctrl_names.get(data[0], f"Ctrl {data[0]}")
    ack_pgn = data[5] | (data[6] << 8) | (data[7] << 16)
    ack_pgn_name = PGN_NAMES.get(ack_pgn, f"PGN 0x{ack_pgn:04X}")

    return {
        "decoded":    f"{ctrl} for {ack_pgn_name}",
        "ack_type":   ctrl,
        "acked_pgn":  f"0x{ack_pgn:04X}",
        "acked_name": ack_pgn_name,
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

    # No-DTC condition: all-zero DTC bytes (many ECUs) or all-0xFF (J1939-73 sentinel)
    if len(data) >= 6 and (data[2:6] == [0, 0, 0, 0] or data[2:6] == [0xFF, 0xFF, 0xFF, 0xFF]):
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


def decode_dm2(data):
    """PGN 0xFECB - Previously Active DTCs (same structure as DM1)."""
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM2 (Historic):")
    return result


# ---------------------------------------------------------------------------
# Additional PGN signal decoders (previously missing)
# ---------------------------------------------------------------------------

def decode_ebc2(data):
    """PGN 0xF003 - Electronic Brake Controller 2
    Byte 0: Front Axle Speed (0.125 km/h per bit, 2-byte)
    Bytes 0-1: Front Axle Speed
    Bytes 2-3: Relative Speed, Front Axle Left Wheel
    Bytes 4-5: Relative Speed, Front Axle Right Wheel
    Bytes 6-7: Relative Speed, Rear Axle #1 Left Wheel
    """
    if len(data) < 8:
        return None
    fa_spd = _speed_kmh(data[0] | (data[1] << 8))
    rel_fal = f"{((data[2] | (data[3] << 8)) * 1.0/512 - 62.5):.3f} km/h" if (data[2] | (data[3] << 8)) != 0xFFFF else "N/A"
    rel_far = f"{((data[4] | (data[5] << 8)) * 1.0/512 - 62.5):.3f} km/h" if (data[4] | (data[5] << 8)) != 0xFFFF else "N/A"
    return {
        "decoded":       f"FrontAxleSpd={fa_spd}  FL_Rel={rel_fal}  FR_Rel={rel_far}",
        "front_axle_spd": fa_spd,
        "rel_fl_wheel":   rel_fal,
        "rel_fr_wheel":   rel_far,
    }


def decode_eac1(data):
    """PGN 0xF009 - Electronic Axle Controller 1
    Byte 0: Drive Axle Location / Drive Axle Liftable Axle Indicator
    Byte 1: Drive Axle #1 Lift Air Pressure (8 kPa/bit)
    Byte 2: Drive Axle #2 Lift Air Pressure (8 kPa/bit)
    Byte 3: Diff Lock Override Switch Status / Diff Lock Engagement Status
    Byte 4: Load on Drive Axle #1 (2 kPa/bit)
    Byte 5: Load on Drive Axle #2 (2 kPa/bit)
    """
    if len(data) < 8:
        return None
    da1_lift = f"{data[1] * 8} kPa" if data[1] != 0xFF else "N/A"
    da2_lift = f"{data[2] * 8} kPa" if data[2] != 0xFF else "N/A"
    diff_lock = _spn_2bit(data[3] & 0x03)
    load_da1  = f"{data[4] * 2} kPa" if data[4] != 0xFF else "N/A"
    load_da2  = f"{data[5] * 2} kPa" if data[5] != 0xFF else "N/A"
    return {
        "decoded":     f"DA1LiftPress={da1_lift}  DA2LiftPress={da2_lift}  DiffLock={diff_lock}  LoadDA1={load_da1}",
        "da1_lift_press": da1_lift,
        "da2_lift_press": da2_lift,
        "diff_lock":      diff_lock,
        "load_da1":       load_da1,
        "load_da2":       load_da2,
    }


def decode_eac2(data):
    """PGN 0xF00A - Electronic Axle Controller 2 (Steer Axle)
    Byte 0: Steer Axle Temperature (offset -40degC)
    Byte 1-2: Steer Axle Lube Pressure (0.5 kPa/bit)
    Byte 3: Traction Control Override Switch
    """
    if len(data) < 8:
        return None
    temp = _temp_c(data[0])
    lube_p = _press16_kpa(data[1] | (data[2] << 8))
    tc_override = _spn_2bit(data[3] & 0x03)
    return {
        "decoded":       f"SteerAxleTemp={temp}  LubePress={lube_p}  TCOverride={tc_override}",
        "steer_axle_temp": temp,
        "lube_press":      lube_p,
        "tc_override":     tc_override,
    }


def decode_erc2(data):
    """PGN 0xF00C - Electronic Retarder Controller 2
    Byte 0: bits 0-1 Transmission Retarder Request
    Byte 1: Requested Retarder Percent Torque
    Byte 2: Actual Maximum Available Retarder Torque
    Byte 4-5: Retarder Road Speed Limit (0.125 km/h per bit)
    """
    if len(data) < 8:
        return None
    req_trq = _pct(data[1])
    max_trq = _pct(data[2])
    spd_lmt = _speed_kmh(data[4] | (data[5] << 8))
    return {
        "decoded":        f"ReqTorque={req_trq}  MaxTorque={max_trq}  SpdLimit={spd_lmt}",
        "req_torque":     req_trq,
        "max_torque":     max_trq,
        "spd_limit":      spd_lmt,
    }


def decode_eec4(data):
    """PGN 0xF010 - Electronic Engine Controller 4
    Bytes 0-1: Estimated Engine Parasitic Losses - Percent Torque
    Bytes 2-3: Turbocharger 1 Compressor Inlet Pressure (0.1 kPa/bit)
    Byte 4: Engine Exhaust 1 Pressure (0.1 kPa/bit, 2-byte)
    Byte 6: Engine Variable Geometry Turbocharger Actuator #1 (0.4%/bit)
    """
    if len(data) < 8:
        return None
    parasitic = _pct(data[0])
    tc_inlet  = _press16_kpa(data[2] | (data[3] << 8), scale=0.1)
    vgt_pos   = _pct_raw(data[6], 0.4)
    return {
        "decoded":    f"Parasitic={parasitic}  TC1InletPress={tc_inlet}  VGT={vgt_pos}",
        "parasitic":  parasitic,
        "tc1_inlet":  tc_inlet,
        "vgt_pos":    vgt_pos,
    }


def decode_gfr(data):
    """PGN 0xF011 - Engine Gas Flow Rate
    Bytes 0-1: Engine Intake Air Mass Flow Rate (0.05 kg/h per bit)
    Bytes 2-3: Engine Exhaust Gas Mass Flow Rate (0.05 kg/h per bit)
    Bytes 4-5: Engine Intake Air Volumetric Flow Rate (0.1 m^3/h per bit)
    """
    if len(data) < 8:
        return None
    intake_mass = f"{(data[0] | (data[1] << 8)) * 0.05:.2f} kg/h" if (data[0] | (data[1] << 8)) != 0xFFFF else "N/A"
    exhaust_mass = f"{(data[2] | (data[3] << 8)) * 0.05:.2f} kg/h" if (data[2] | (data[3] << 8)) != 0xFFFF else "N/A"
    intake_vol   = f"{(data[4] | (data[5] << 8)) * 0.1:.1f} m^3/h" if (data[4] | (data[5] << 8)) != 0xFFFF else "N/A"
    return {
        "decoded":        f"IntakeMass={intake_mass}  ExhaustMass={exhaust_mass}  IntakeVol={intake_vol}",
        "intake_mass_flow":  intake_mass,
        "exhaust_mass_flow": exhaust_mass,
        "intake_vol_flow":   intake_vol,
    }


def decode_eec5(data):
    """PGN 0xF013 - Electronic Engine Controller 5
    Bytes 0-1: Engine Exhaust Gas Pressure (0.1 kPa/bit)
    Byte 2: Engine Fuel Valve 1 Position (0.4%/bit)
    Bytes 4-5: Engine Intake Manifold #1 Pressure - High Resolution (0.1 kPa/bit)
    """
    if len(data) < 8:
        return None
    exh_press  = _press16_kpa(data[0] | (data[1] << 8), scale=0.1)
    fuel_valve = _pct_raw(data[2], 0.4)
    man_press  = _press16_kpa(data[4] | (data[5] << 8), scale=0.1)
    return {
        "decoded":      f"ExhaustPress={exh_press}  FuelValve={fuel_valve}  ManifoldPress={man_press}",
        "exhaust_press": exh_press,
        "fuel_valve":    fuel_valve,
        "manifold_press": man_press,
    }


def decode_eec6(data):
    """PGN 0xF034 - Electronic Engine Controller 6
    Byte 0: Engine Throttle Actuator #1 Control Command (0.4%/bit)
    Byte 1: Engine Throttle Actuator #2 Control Command (0.4%/bit)
    Bytes 2-3: Engine Throttle Valve #1 Position (0.4%/bit, 2-byte for higher res)
    """
    if len(data) < 8:
        return None
    throttle1 = _pct_raw(data[0], 0.4)
    throttle2 = _pct_raw(data[1], 0.4)
    tv1_pos   = _pct_raw(data[2], 0.4)
    return {
        "decoded":    f"Throttle1={throttle1}  Throttle2={throttle2}  TV1Pos={tv1_pos}",
        "throttle1":  throttle1,
        "throttle2":  throttle2,
        "tv1_pos":    tv1_pos,
    }


def decode_gfc(data):
    """PGN 0xF020 - Fuel Consumption (Gaseous)
    Bytes 0-3: Total Gaseous Fuel Used (Natural Gas) (0.001 kg/bit)
    Bytes 4-7: Trip Gaseous Fuel Used (0.001 kg/bit)
    """
    if len(data) < 8:
        return None
    total_raw = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    trip_raw  = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
    total_fuel = f"{total_raw * 0.001:.3f} kg" if total_raw != 0xFFFFFFFF else "N/A"
    trip_fuel  = f"{trip_raw * 0.001:.3f} kg"  if trip_raw  != 0xFFFFFFFF else "N/A"
    return {
        "decoded":      f"TotalGasFuel={total_fuel}  TripGasFuel={trip_fuel}",
        "total_gas_fuel": total_fuel,
        "trip_gas_fuel":  trip_fuel,
    }


def decode_tc1(data):
    """PGN 0xFEF6 - Transmission Configuration 1
    Byte 0: Transmission Number of Gears (Forward)
    Byte 1: Transmission Requested Range (Forward gear positions)
    Byte 2: Transmission Requested Range (Reverse gear positions)
    Byte 3: Transmission Requested Gear feedback
    Bytes 4-5: Transmission Ratio in Neutral (0.001/bit)
    """
    if len(data) < 8:
        return None
    fwd_gears = data[0] if data[0] != 0xFF else "N/A"
    rev_gears = data[1] if data[1] != 0xFF else "N/A"
    neutral_ratio = _ratio(data[4] | (data[5] << 8))
    return {
        "decoded":       f"FwdGears={fwd_gears}  RevGears={rev_gears}  NeutralRatio={neutral_ratio}",
        "fwd_gears":     str(fwd_gears),
        "rev_gears":     str(rev_gears),
        "neutral_ratio": neutral_ratio,
    }


def decode_pto(data):
    """PGN 0xFEF8 - Power Takeoff Information
    Byte 0: bits 0-1 PTO State / bits 2-3 Remote PTO Variable Speed Enable Status
    Byte 1: PTO Drive Engagement (0.4%/bit)
    Bytes 2-3: PTO Speed (0.125 RPM/bit)
    Byte 4: PTO Set Speed (1 RPM/bit)
    Byte 5: bits 0-1 PTO Engagement Control / bits 2-3 Remote PTO Preprogrammed Speed Ctrl Enable
    Bytes 6-7: PTO Output Shaft Speed (0.125 RPM/bit)
    """
    if len(data) < 8:
        return None
    pto_state_raw = data[0] & 0x0F
    pto_states = {0: "Off/Disabled", 1: "Hold", 2: "Remote Hold", 3: "Standby",
                  4: "Remote Standby", 5: "Set", 6: "Decel", 7: "Resume",
                  8: "Accel", 10: "PTO Active", 11: "Remote PTO Active", 15: "N/A"}
    pto_state = pto_states.get(pto_state_raw, f"State {pto_state_raw}")
    pto_speed  = _rpm(data[2] | (data[3] << 8))
    set_speed  = f"{data[4]} RPM" if data[4] != 0xFF else "N/A"
    out_speed  = _rpm(data[6] | (data[7] << 8))
    return {
        "decoded":    f"PTOState={pto_state}  Speed={pto_speed}  SetSpeed={set_speed}  OutSpeed={out_speed}",
        "pto_state":  pto_state,
        "pto_speed":  pto_speed,
        "set_speed":  set_speed,
        "out_speed":  out_speed,
    }


def decode_ccss(data):
    """PGN 0xFEF9 - Cruise Control / Vehicle Speed Setup
    Byte 0: Maximum Vehicle Speed Limit (1 km/h per bit)
    Byte 1: Cruise Control High Set Limit Speed (1 km/h per bit)
    Byte 2: Cruise Control Low Set Limit Speed (1 km/h per bit)
    Byte 3: Cruise Control Preset Speed 1 (1 km/h per bit)
    Byte 4: Cruise Control Preset Speed 2 (1 km/h per bit)
    """
    if len(data) < 8:
        return None
    max_spd    = f"{data[0]} km/h" if data[0] != 0xFF else "N/A"
    cc_hi      = f"{data[1]} km/h" if data[1] != 0xFF else "N/A"
    cc_lo      = f"{data[2]} km/h" if data[2] != 0xFF else "N/A"
    preset1    = f"{data[3]} km/h" if data[3] != 0xFF else "N/A"
    preset2    = f"{data[4]} km/h" if data[4] != 0xFF else "N/A"
    return {
        "decoded":      f"MaxSpeed={max_spd}  CC_Hi={cc_hi}  CC_Lo={cc_lo}  Preset1={preset1}  Preset2={preset2}",
        "max_speed":    max_spd,
        "cc_high_lmt":  cc_hi,
        "cc_low_lmt":   cc_lo,
        "preset_spd1":  preset1,
        "preset_spd2":  preset2,
    }


def decode_tire(data):
    """PGN 0xFEFA - Tire Condition (first 8 bytes; full message is TP multi-packet)
    Byte 0: Tire Location
    Byte 1: bits 0-1 Tire Pressure Extended Range
    Byte 2: Tire Pressure (4 kPa/bit)
    Bytes 3-4: Tire Temperature (0.03125 K/bit, offset -273degC)
    Byte 5: Tire Pressure Threshold Detection (encoded)
    """
    if len(data) < 8:
        return None
    location  = data[0] if data[0] != 0xFF else "N/A"
    pressure  = f"{data[2] * 4} kPa" if data[2] != 0xFF else "N/A"
    temp_raw  = data[3] | (data[4] << 8)
    temp      = _temp16_c(temp_raw)
    return {
        "decoded":     f"TireLoc={location}  Pressure={pressure}  Temp={temp}",
        "tire_loc":    str(location),
        "tire_press":  pressure,
        "tire_temp":   temp,
    }


def decode_fsp(data):
    """PGN 0xFEFB - Fuel Supply Pressure
    Bytes 0-1: Fuel Supply Pressure (0.1 kPa/bit)
    Bytes 2-3: Fuel Filter Differential Pressure (0.1 kPa/bit)
    """
    if len(data) < 4:
        return None
    supply_press = _press16_kpa(data[0] | (data[1] << 8), scale=0.1)
    filter_dp    = _press16_kpa(data[2] | (data[3] << 8), scale=0.1)
    return {
        "decoded":       f"SupplyPress={supply_press}  FilterDP={filter_dp}",
        "supply_press":  supply_press,
        "filter_dp":     filter_dp,
    }


def decode_ci(data):
    """PGN 0xFEFC - Cab Illumination Message
    Byte 0: Cab Interior Working Light (0.4%/bit)
    Byte 1: Main Light Switch (bits)
    Byte 2: Dashboard Illumination (0.4%/bit)
    """
    if len(data) < 8:
        return None
    interior = _pct_raw(data[0], 0.4)
    dash     = _pct_raw(data[2], 0.4)
    main_sw  = _spn_2bit(data[1] & 0x03)
    return {
        "decoded":     f"Interior={interior}  Dashboard={dash}  MainSwitch={main_sw}",
        "interior":    interior,
        "dashboard":   dash,
        "main_switch": main_sw,
    }


def decode_ccc(data):
    """PGN 0xFEFD - Cab Climate Control
    Byte 0: bits 0-1 HVAC Mode / bits 2-3 Blower Bypass Status
    Byte 1: Cab Interior Target Temperature (offset -40degC)
    Byte 2: Climate Control Status (bits)
    Byte 3: Cab Fan Speed (0.4%/bit)
    """
    if len(data) < 8:
        return None
    hvac_mode_raw = data[0] & 0x0F
    hvac_modes = {0: "Off", 1: "Auto", 2: "Heat", 3: "Cool", 4: "Vent", 5: "Dehumidify", 15: "N/A"}
    hvac_mode = hvac_modes.get(hvac_mode_raw, f"Mode {hvac_mode_raw}")
    target_temp = _temp_c(data[1])
    fan_speed   = _pct_raw(data[3], 0.4)
    return {
        "decoded":      f"HVAC={hvac_mode}  TargetTemp={target_temp}  FanSpeed={fan_speed}",
        "hvac_mode":    hvac_mode,
        "target_temp":  target_temp,
        "fan_speed":    fan_speed,
    }


def decode_bt(data):
    """PGN 0xFEFF - Battery Temperature
    Bytes 0-1: Battery Temperature (0.03125 K/bit, offset -273degC)
    Bytes 2-3: Battery #2 Temperature (0.03125 K/bit, offset -273degC)
    """
    if len(data) < 4:
        return None
    bat1 = _temp16_c(data[0] | (data[1] << 8))
    bat2 = _temp16_c(data[2] | (data[3] << 8)) if len(data) >= 4 else "N/A"
    return {
        "decoded":    f"Bat1Temp={bat1}  Bat2Temp={bat2}",
        "bat1_temp":  bat1,
        "bat2_temp":  bat2,
    }


def decode_vh(data):
    """PGN 0xFEEE - Vehicle Hours
    Bytes 0-3: Total Vehicle Hours (0.05 h/bit)
    Bytes 4-7: Total Power Takeoff Hours (0.05 h/bit)
    """
    if len(data) < 8:
        return None
    veh_hrs = _hours(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24))
    pto_hrs = _hours(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24))
    return {
        "decoded":     f"VehicleHours={veh_hrs}  PTOHours={pto_hrs}",
        "veh_hours":   veh_hrs,
        "pto_hours":   pto_hrs,
    }


def decode_io(data):
    """PGN 0xFEED - Idle Operation
    Bytes 0-3: Total Engine Idle Hours (0.05 h/bit)
    Bytes 4-7: Total Engine Idle Fuel Used (0.5 L/bit)
    """
    if len(data) < 8:
        return None
    idle_hrs_raw = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    idle_hrs     = _hours(idle_hrs_raw)
    idle_fuel_raw = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
    idle_fuel    = f"{idle_fuel_raw * 0.5:.1f} L" if idle_fuel_raw != 0xFFFFFFFF else "N/A"
    return {
        "decoded":      f"IdleHours={idle_hrs}  IdleFuel={idle_fuel}",
        "idle_hours":   idle_hrs,
        "idle_fuel":    idle_fuel,
    }


def decode_vi(data):
    """PGN 0xFEEC - Vehicle Identification (ASCII VIN, up to 17+ chars via TP)"""
    try:
        vin = "".join(chr(b) for b in data if 0x20 <= b <= 0x7E).strip("*").strip()
    except Exception:
        vin = "N/A"
    return {
        "decoded": f"VIN={vin}",
        "vin":     vin,
    }


def decode_dm3(data):
    """PGN 0xFECC - Diagnostic Data Clear / Reset (DM3)
    No significant signal content -- just the broadcast trigger.
    """
    return {"decoded": "DM3: Clear/Reset Diagnostic Info Request"}


def decode_dm5(data):
    """PGN 0xFECE - Diagnostic Readiness 1 (DM5)
    Byte 0: Active Fault Indicator Lamp Status
    Byte 1: Previously Active Fault Indicator Lamp Status
    Byte 2: OBD Compliance (encoded)
    Byte 3: Continuous Monitor Systems Supported / Ready
    Bytes 4-5: Once-per-Trip Monitor Systems Supported
    Bytes 6-7: Once-per-Trip Monitor Systems Complete
    """
    if len(data) < 8:
        return None
    active_lamps = data[0]
    prev_lamps   = data[1]
    obd_raw      = data[2]
    obd_names = {1: "OBD II (CARB)", 2: "OBD (EPA)", 3: "OBD + OBD II",
                 4: "OBD I", 5: "Not OBD", 6: "EOBD", 13: "EMD", 14: "EMD+", 15: "HD OBD",
                 16: "WWH OBD"}
    obd_compliance = obd_names.get(obd_raw, f"Type {obd_raw}")
    return {
        "decoded":        f"ActiveLamps={active_lamps}  PrevLamps={prev_lamps}  OBD={obd_compliance}",
        "active_lamps":   str(active_lamps),
        "prev_lamps":     str(prev_lamps),
        "obd_compliance": obd_compliance,
    }


def decode_dm6(data):
    """PGN 0xFECF - Emission-Related Pending DTCs (DM6) -- same structure as DM1."""
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM6 (Pending):")
    return result


def decode_dm7(data):
    """PGN 0xFED0 - Command Non-Continuous Monitor Test (DM7)
    Byte 0: Test Identifier
    Bytes 1-2: SPN to Test
    Byte 3: FMI to Test
    """
    if len(data) < 4:
        return None
    test_id = data[0]
    spn     = data[1] | (data[2] << 8)
    fmi     = data[3] & 0x1F
    return {
        "decoded":   f"TestID={test_id}  SPN={spn}  FMI={fmi}",
        "test_id":   str(test_id),
        "spn":       str(spn),
        "fmi":       str(fmi),
    }


def decode_dm8(data):
    """PGN 0xFED8 - Test Results (DM8)
    Byte 0: Test Identifier
    Bytes 1-2: SPN
    Byte 3: FMI
    Bytes 4-5: Test Value
    Bytes 6-7: Max/Min Limit
    """
    if len(data) < 8:
        return None
    test_id   = data[0]
    spn       = data[1] | (data[2] << 8)
    fmi       = data[3] & 0x1F
    test_val  = data[4] | (data[5] << 8)
    limit_val = data[6] | (data[7] << 8)
    return {
        "decoded":    f"TestID={test_id}  SPN={spn}  FMI={fmi}  Value=0x{test_val:04X}  Limit=0x{limit_val:04X}",
        "test_id":    str(test_id),
        "spn":        str(spn),
        "fmi":        str(fmi),
        "test_value": f"0x{test_val:04X}",
        "limit_val":  f"0x{limit_val:04X}",
    }


def decode_dm21(data):
    """PGN 0xFEDB - Diagnostic Readiness 2 (DM21)
    Bytes 0-1: Distance Traveled While MIL is Active (0.125 km/bit)
    Bytes 2-3: Distance Since DTCs Cleared (0.125 km/bit)
    Bytes 4-5: Minutes Run by Engine While MIL is Activated (1 min/bit)
    Bytes 6-7: Time Since Diagnostic Trouble Codes Cleared (1 min/bit)
    """
    if len(data) < 8:
        return None
    mil_dist_raw = data[0] | (data[1] << 8)
    mil_dist   = f"{mil_dist_raw * 0.125:.1f} km" if mil_dist_raw != 0xFFFF else "N/A"
    clr_dist_raw = data[2] | (data[3] << 8)
    clr_dist   = f"{clr_dist_raw * 0.125:.1f} km" if clr_dist_raw != 0xFFFF else "N/A"
    mil_time_raw = data[4] | (data[5] << 8)
    mil_time   = f"{mil_time_raw} min" if mil_time_raw != 0xFFFF else "N/A"
    clr_time_raw = data[6] | (data[7] << 8)
    clr_time   = f"{clr_time_raw} min" if clr_time_raw != 0xFFFF else "N/A"
    return {
        "decoded":      f"MIL_Dist={mil_dist}  ClearDist={clr_dist}  MIL_Time={mil_time}  ClearTime={clr_time}",
        "mil_dist":     mil_dist,
        "clear_dist":   clr_dist,
        "mil_time":     mil_time,
        "clear_time":   clr_time,
    }


def decode_bmsh(data):
    """PGN 0xFD09 - Battery Main Switch Hold Request
    Byte 0: bits 0-1 Battery Main Switch Hold Request
    """
    if len(data) < 1:
        return None
    hold_req = _spn_2bit(data[0] & 0x03)
    return {
        "decoded":   f"HoldRequest={hold_req}",
        "hold_req":  hold_req,
    }


def decode_aegr1(data):
    """PGN 0xFD7D - Engine Exhaust Gas Recirculation 1
    Bytes 0-1: Engine EGR Valve Position (0.0025%/bit)
    Byte 2: Engine EGR Mass Flow Rate error (encoded)
    Bytes 4-5: Engine EGR Temperature (0.03125 K/bit, offset -273degC)
    """
    if len(data) < 8:
        return None
    valve_pos_raw = data[0] | (data[1] << 8)
    valve_pos = f"{valve_pos_raw * 0.0025:.2f}%" if valve_pos_raw != 0xFFFF else "N/A"
    egr_temp_raw  = data[4] | (data[5] << 8)
    egr_temp  = _temp16_c(egr_temp_raw)
    return {
        "decoded":    f"EGRValve={valve_pos}  EGRTemp={egr_temp}",
        "egr_valve":  valve_pos,
        "egr_temp":   egr_temp,
    }


def decode_at1t1i(data):
    """PGN 0xFDB5 - Aftertreatment 1 DEF Tank Information
    Byte 0: Aftertreatment 1 DEF Tank Level (0.4%/bit)
    Byte 1: Aftertreatment 1 DEF Tank Temperature (offset -40degC)
    Bytes 2-3: Aftertreatment 1 DEF Tank Volume (0.1 L/bit)
    Byte 4: Aftertreatment 1 DEF Concentration (0.4%/bit)
    """
    if len(data) < 8:
        return None
    level   = _pct_raw(data[0], 0.4)
    temp    = _temp_c(data[1])
    vol_raw = data[2] | (data[3] << 8)
    volume  = f"{vol_raw * 0.1:.1f} L" if vol_raw != 0xFFFF else "N/A"
    conc    = _pct_raw(data[4], 0.4)
    return {
        "decoded":     f"DEFLevel={level}  DEFTemp={temp}  DEFVol={volume}  DEFConc={conc}",
        "def_level":   level,
        "def_temp":    temp,
        "def_volume":  volume,
        "def_conc":    conc,
    }


def decode_at1psdp(data):
    """PGN 0xFDB8 - Aftertreatment 1 Diesel Particulate Filter (Pressure / Soot)
    Bytes 0-1: AT1 DPF Differential Pressure (0.1 kPa/bit)
    Bytes 2-3: AT1 Outlet Temperature (0.03125 K/bit, offset -273degC)
    Byte 4: AT1 DPF Status (bits)
    Bytes 6-7: AT1 DPF Soot Load Regeneration Threshold (0.4%/bit)
    """
    if len(data) < 8:
        return None
    dpf_dp      = _press16_kpa(data[0] | (data[1] << 8), scale=0.1)
    outlet_raw  = data[2] | (data[3] << 8)
    outlet_temp = _temp16_c(outlet_raw)
    soot_thresh = _pct_raw(data[6], 0.4)
    return {
        "decoded":      f"DPF_DP={dpf_dp}  OutletTemp={outlet_temp}  SootThresh={soot_thresh}",
        "dpf_dp":       dpf_dp,
        "outlet_temp":  outlet_temp,
        "soot_thresh":  soot_thresh,
    }


def decode_atpfdc(data):
    """PGN 0xFDB9 - Aftertreatment DPF Control
    Byte 0: AT1 DPF Active Regeneration Status
    Byte 1: AT1 DPF Passive Regeneration Status
    Byte 2: AT1 DPF Regeneration Inhibit Switch Status
    """
    if len(data) < 8:
        return None
    active_regen  = _spn_2bit(data[0] & 0x03)
    passive_regen = _spn_2bit(data[1] & 0x03)
    inhibit_sw    = _spn_2bit(data[2] & 0x03)
    return {
        "decoded":       f"ActiveRegen={active_regen}  PassiveRegen={passive_regen}  InhibitSW={inhibit_sw}",
        "active_regen":  active_regen,
        "passive_regen": passive_regen,
        "inhibit_sw":    inhibit_sw,
    }


def decode_at1og(data):
    """PGN 0xFDBA - Aftertreatment 1 Outlet Gas
    Bytes 0-1: AT1 SCR Outlet NOx (0.05 ppm/bit)
    Bytes 2-3: AT1 SCR Outlet NH3 (0.1 ppm/bit)
    Bytes 4-5: AT1 Outlet Temperature (0.03125 K/bit, offset -273degC)
    """
    if len(data) < 8:
        return None
    nox_raw = data[0] | (data[1] << 8)
    nox     = f"{nox_raw * 0.05:.2f} ppm" if nox_raw != 0xFFFF else "N/A"
    nh3_raw = data[2] | (data[3] << 8)
    nh3     = f"{nh3_raw * 0.1:.1f} ppm" if nh3_raw != 0xFFFF else "N/A"
    out_raw = data[4] | (data[5] << 8)
    out_temp = _temp16_c(out_raw)
    return {
        "decoded":     f"SCR_NOx={nox}  SCR_NH3={nh3}  OutletTemp={out_temp}",
        "scr_nox":     nox,
        "scr_nh3":     nh3,
        "outlet_temp": out_temp,
    }




# ---------------------------------------------------------------------------
# J1939-71 additional decoders
# ---------------------------------------------------------------------------

def decode_tsc1(data):
    """PGN 0xFEEA - Torque/Speed Control 1 (PDU1 peer-to-peer)
    Byte 0: bits 0-3 Override Control Mode
            bits 4-5 Requested Speed Control Conditions
            bits 6-7 Override Control Mode Priority
    Byte 1: Requested Speed / Speed Limit (0.125 RPM/bit)
    Byte 2: Requested Torque / Torque Limit (offset -125%)
    Byte 3: TSC1 Transmission Rate
    Byte 4: TSC1 Control Purpose
    """
    if len(data) < 5:
        return None
    mode_raw = data[0] & 0x0F
    mode_names = {0: "Override disabled", 1: "Speed control", 2: "Torque control",
                  3: "Speed/Torque limit", 14: "Other", 15: "N/A"}
    mode = mode_names.get(mode_raw, f"Mode {mode_raw}")
    priority_raw = (data[0] >> 6) & 0x03
    priority_names = {0: "Highest", 1: "High", 2: "Medium", 3: "Low"}
    priority = priority_names.get(priority_raw, str(priority_raw))
    req_speed = _rpm(data[1] | (data[2] << 8)) if len(data) > 2 else "N/A"
    req_torque = _pct(data[3]) if len(data) > 3 else "N/A"
    return {
        "decoded":     f"Mode={mode}  ReqSpeed={req_speed}  ReqTorque={req_torque}  Priority={priority}",
        "ctrl_mode":   mode,
        "req_speed":   req_speed,
        "req_torque":  req_torque,
        "priority":    priority,
    }


def decode_td(data):
    """PGN 0xFEE5 - Time/Date
    Byte 0: Seconds (0.25 s/bit)
    Byte 1: Minutes (1 min/bit)
    Byte 2: Hours (1 h/bit)
    Byte 3: Month (1/bit)
    Byte 4: Day (0.25 day/bit)
    Byte 5: Year (1 year/bit, offset 1985)
    Byte 6: Local Minute Offset (1 min/bit, offset -125)
    Byte 7: Local Hour Offset (1 h/bit, offset -125)
    """
    if len(data) < 6:
        return None
    seconds = f"{data[0] * 0.25:.2f}s" if data[0] != 0xFF else "N/A"
    minutes = f"{data[1]}m"            if data[1] != 0xFF else "N/A"
    hours   = f"{data[2]}h"            if data[2] != 0xFF else "N/A"
    month   = f"{data[3]}"             if data[3] != 0xFF else "N/A"
    day     = f"{data[4] * 0.25:.2f}"  if data[4] != 0xFF else "N/A"
    year    = f"{1985 + data[5]}"      if data[5] != 0xFF else "N/A"
    return {
        "decoded":  f"Date={year}-{month}-{day}  Time={hours}:{minutes}:{seconds}",
        "year":     year,
        "month":    month,
        "day":      day,
        "hours":    hours,
        "minutes":  minutes,
        "seconds":  seconds,
    }


def decode_soft(data):
    """PGN 0xFEE3 - Software Identification
    ASCII fields separated by delimiter 0x2A ('*').
    Multi-packet TP is typical.
    """
    try:
        raw = "".join(chr(b) for b in data if 0x20 <= b <= 0x7E)
        parts = [p.strip() for p in raw.split("*") if p.strip()]
        soft_str = " | ".join(parts) if parts else "N/A"
    except Exception:
        soft_str = "N/A"
    return {
        "decoded":  f"SoftwareID={soft_str}",
        "software_id": soft_str,
    }


def decode_ecuh(data):
    """PGN 0xFEE4 - ECU History
    Byte 0: Number of ECU Power Cycles (4-byte)
    Bytes 4-7: Total ECU Operating Hours (0.05 h/bit)
    """
    if len(data) < 8:
        return None
    power_cycles = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    op_hours = _hours(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24))
    cycles_str = str(power_cycles) if power_cycles != 0xFFFFFFFF else "N/A"
    return {
        "decoded":       f"PowerCycles={cycles_str}  OperatingHours={op_hours}",
        "power_cycles":  cycles_str,
        "op_hours":      op_hours,
    }


def decode_hrvd(data):
    """PGN 0xFEC1 - High Resolution Vehicle Distance
    Bytes 0-3: High Resolution Trip Distance (5 m/bit)
    Bytes 4-7: High Resolution Total Vehicle Distance (5 m/bit)
    """
    if len(data) < 8:
        return None
    trip_raw  = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    total_raw = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
    trip  = f"{trip_raw * 5 / 1000:.3f} km"  if trip_raw  != 0xFFFFFFFF else "N/A"
    total = f"{total_raw * 5 / 1000:.3f} km" if total_raw != 0xFFFFFFFF else "N/A"
    return {
        "decoded":    f"TripDist={trip}  TotalDist={total}",
        "trip_dist":  trip,
        "total_dist": total,
    }


def decode_hretf(data):
    """PGN 0xFEC2 - High Resolution Engine Total Fuel Used
    Bytes 0-3: High Resolution Engine Trip Fuel (0.001 L/bit)
    Bytes 4-7: High Resolution Engine Total Fuel Used (0.001 L/bit)
    """
    if len(data) < 8:
        return None
    trip_raw  = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    total_raw = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
    trip  = f"{trip_raw  * 0.001:.3f} L" if trip_raw  != 0xFFFFFFFF else "N/A"
    total = f"{total_raw * 0.001:.3f} L" if total_raw != 0xFFFFFFFF else "N/A"
    return {
        "decoded":      f"TripFuel={trip}  TotalFuel={total}",
        "trip_fuel":    trip,
        "total_fuel":   total,
    }


def decode_esc(data):
    """PGN 0xFEC3 - Electronic Steering Controller
    Bytes 0-1: Steering Wheel Angle (1/1024 deg/bit, offset -31.374 deg)
    Byte 2: Steering Wheel Turn Counter
    Bytes 3-4: Steering Wheel Angle Sensor (0.0439453125 deg/bit, offset -1440 deg)
    Byte 5: Steering Wheel Rotational Velocity (1 rpm/bit, offset -125)
    """
    if len(data) < 6:
        return None
    angle_raw = data[0] | (data[1] << 8)
    angle = f"{angle_raw / 1024.0 - 31.374:.3f}deg" if angle_raw != 0xFFFF else "N/A"
    turn_cnt = str(data[2]) if data[2] != 0xFF else "N/A"
    rot_vel = f"{data[5] - 125} rpm" if len(data) > 5 and data[5] != 0xFF else "N/A"
    return {
        "decoded":       f"SteerAngle={angle}  TurnCount={turn_cnt}  RotVel={rot_vel}",
        "steer_angle":   angle,
        "turn_count":    turn_cnt,
        "rot_velocity":  rot_vel,
    }


def decode_tf2(data):
    """PGN 0xFEB0 - Transmission Fluids 2
    Byte 0: Transmission Clutch 3 Pressure (1.6 kPa/bit)
    Byte 1: Transmission Clutch 4 Pressure (1.6 kPa/bit)
    Bytes 2-3: Transmission Oil Temperature 2 (0.03125 K/bit, offset -273degC)
    Byte 4: Transmission Lube Pressure (0.5 kPa/bit)
    Byte 5-6: Transmission Retarder Pressure (0.5 kPa/bit)
    """
    if len(data) < 8:
        return None
    cl3 = f"{data[0] * 1.6:.1f} kPa" if data[0] != 0xFF else "N/A"
    cl4 = f"{data[1] * 1.6:.1f} kPa" if data[1] != 0xFF else "N/A"
    oil_raw = data[2] | (data[3] << 8)
    oil_temp = _temp16_c(oil_raw)
    lube_p = _press_kpa(data[4])
    return {
        "decoded":       f"OilTemp2={oil_temp}  LubePress={lube_p}  Cl3={cl3}  Cl4={cl4}",
        "oil_temp2":     oil_temp,
        "lube_press":    lube_p,
        "clutch3_press": cl3,
        "clutch4_press": cl4,
    }


def decode_eflp2(data):
    """PGN 0xFEB4 - Engine Fluid Level/Pressure 2
    Byte 0: Engine Injection Control Pressure (0.5 kPa/bit)
    Byte 1: Engine Injector Metering Rail 1 Pressure (0.5 kPa/bit)
    Bytes 2-3: Engine Injector Metering Rail 2 Pressure (0.1 kPa/bit)
    Byte 4: Engine Variable Geometry Turbo Actuator 2 (0.4%/bit)
    Byte 5: Engine Wastegate Actuator 1 Position (0.4%/bit)
    Byte 6: Engine Turbocharger 1 Oil Pressure (4 kPa/bit)
    """
    if len(data) < 8:
        return None
    inj_ctrl_p = _press_kpa(data[0])
    rail1_p    = _press_kpa(data[1])
    rail2_raw  = data[2] | (data[3] << 8)
    rail2_p    = _press16_kpa(rail2_raw, scale=0.1)
    wastegate  = _pct_raw(data[5], 0.4)
    tc_oil_p   = f"{data[6] * 4} kPa" if data[6] != 0xFF else "N/A"
    return {
        "decoded":        f"InjCtrlP={inj_ctrl_p}  Rail1P={rail1_p}  Rail2P={rail2_p}  Wastegate={wastegate}",
        "inj_ctrl_press": inj_ctrl_p,
        "rail1_press":    rail1_p,
        "rail2_press":    rail2_p,
        "wastegate_pos":  wastegate,
        "tc_oil_press":   tc_oil_p,
    }


def decode_gfe(data):
    """PGN 0xFEB5 - Fuel Economy (Gaseous)
    Bytes 0-1: Engine Gaseous Fuel Rate (0.05 kg/h per bit)
    Bytes 2-3: Engine Instantaneous Gaseous Fuel Economy (1/512 km/kg per bit)
    Bytes 4-5: Engine Average Gaseous Fuel Economy (1/512 km/kg per bit)
    """
    if len(data) < 6:
        return None
    rate_raw = data[0] | (data[1] << 8)
    rate = f"{rate_raw * 0.05:.2f} kg/h" if rate_raw != 0xFFFF else "N/A"
    inst_raw = data[2] | (data[3] << 8)
    inst = f"{inst_raw / 512.0:.3f} km/kg" if inst_raw != 0xFFFF else "N/A"
    avg_raw = data[4] | (data[5] << 8)
    avg = f"{avg_raw / 512.0:.3f} km/kg" if avg_raw != 0xFFFF else "N/A"
    return {
        "decoded":       f"GasRate={rate}  InstEco={inst}  AvgEco={avg}",
        "gas_fuel_rate": rate,
        "inst_gas_eco":  inst,
        "avg_gas_eco":   avg,
    }


def decode_agfe(data):
    """PGN 0xFEB6 - Average Fuel Economy (Gaseous)
    Bytes 0-1: Average Gaseous Fuel Economy since reset (1/512 km/kg)
    Bytes 2-3: Average Gaseous Fuel Economy (lifetime) (1/512 km/kg)
    """
    if len(data) < 4:
        return None
    since_raw = data[0] | (data[1] << 8)
    since = f"{since_raw / 512.0:.3f} km/kg" if since_raw != 0xFFFF else "N/A"
    life_raw  = data[2] | (data[3] << 8)
    life  = f"{life_raw / 512.0:.3f} km/kg" if life_raw  != 0xFFFF else "N/A"
    return {
        "decoded":         f"SinceReset={since}  Lifetime={life}",
        "eco_since_reset": since,
        "eco_lifetime":    life,
    }


def decode_et2(data):
    """PGN 0xFEBD - Engine Temperature 2
    Byte 0: Engine Intercooler Thermostat Opening (0.4%/bit)
    Byte 1: Engine Coolant Thermostat Opening (0.4%/bit)
    Bytes 2-3: Engine Turbo Oil Temperature (0.03125 K/bit, offset -273degC)
    Bytes 4-5: Engine Piston Cooling Oil Temperature (0.03125 K/bit, offset -273degC)
    Byte 6: Engine Coolant Temperature 2 (offset -40degC)
    Byte 7: Engine Fuel Temperature 2 (offset -40degC)
    """
    if len(data) < 8:
        return None
    intc_therm  = _pct_raw(data[0], 0.4)
    cool_therm  = _pct_raw(data[1], 0.4)
    turbo_raw   = data[2] | (data[3] << 8)
    turbo_temp  = _temp16_c(turbo_raw)
    piston_raw  = data[4] | (data[5] << 8)
    piston_temp = _temp16_c(piston_raw)
    coolant2    = _temp_c(data[6])
    fuel2       = _temp_c(data[7])
    return {
        "decoded":          f"TurboOilTemp={turbo_temp}  PistonOilTemp={piston_temp}  Coolant2={coolant2}",
        "turbo_oil_temp":   turbo_temp,
        "piston_oil_temp":  piston_temp,
        "coolant2_temp":    coolant2,
        "fuel2_temp":       fuel2,
        "intc_therm_open":  intc_therm,
        "cool_therm_open":  cool_therm,
    }


def decode_gfc2(data):
    """PGN 0xFEC0 - Fuel Consumption (Gaseous) 2
    Bytes 0-3: Total Gaseous Fuel Used 2 (0.001 kg/bit)
    Bytes 4-7: Trip Gaseous Fuel Used 2 (0.001 kg/bit)
    """
    if len(data) < 8:
        return None
    total_raw = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    trip_raw  = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
    total = f"{total_raw * 0.001:.3f} kg" if total_raw != 0xFFFFFFFF else "N/A"
    trip  = f"{trip_raw  * 0.001:.3f} kg" if trip_raw  != 0xFFFFFFFF else "N/A"
    return {
        "decoded":       f"TotalGas2={total}  TripGas2={trip}",
        "total_gas2":    total,
        "trip_gas2":     trip,
    }


def decode_eec7(data):
    """PGN 0xFEA8 - Electronic Engine Controller 7
    Byte 0: Engine Fuel Injection Control Pressure Command (0.5 kPa/bit)
    Byte 1-2: Commanded Fuel Rail Pressure (2 kPa/bit)
    Byte 3-4: Engine Actual Fuel Rail Pressure (2 kPa/bit)
    Byte 5: Engine Fuel Rail Pressure Control Status
    """
    if len(data) < 8:
        return None
    inj_press = _press_kpa(data[0])
    cmd_rail  = f"{(data[1] | (data[2] << 8)) * 2} kPa" if (data[1] | (data[2] << 8)) != 0xFFFF else "N/A"
    act_rail  = f"{(data[3] | (data[4] << 8)) * 2} kPa" if (data[3] | (data[4] << 8)) != 0xFFFF else "N/A"
    return {
        "decoded":       f"InjPress={inj_press}  CmdRailP={cmd_rail}  ActRailP={act_rail}",
        "inj_press":     inj_press,
        "cmd_rail_press": cmd_rail,
        "act_rail_press": act_rail,
    }


def decode_eth(data):
    """PGN 0xFEA9 - Engine Torque History
    Bytes 0-1: Time at Max Torque (1 h/bit)
    Bytes 2-3: Time Motoring (1 h/bit)
    Bytes 4-5: Time at Max Power (1 h/bit)
    Bytes 6-7: Time at Idle (1 h/bit)
    """
    if len(data) < 8:
        return None
    t_max_torq = f"{data[0] | (data[1] << 8)} h" if (data[0] | (data[1] << 8)) != 0xFFFF else "N/A"
    t_motor    = f"{data[2] | (data[3] << 8)} h" if (data[2] | (data[3] << 8)) != 0xFFFF else "N/A"
    t_max_pwr  = f"{data[4] | (data[5] << 8)} h" if (data[4] | (data[5] << 8)) != 0xFFFF else "N/A"
    t_idle     = f"{data[6] | (data[7] << 8)} h" if (data[6] | (data[7] << 8)) != 0xFFFF else "N/A"
    return {
        "decoded":         f"MaxTorqueTime={t_max_torq}  MotoringTime={t_motor}  MaxPwrTime={t_max_pwr}  IdleTime={t_idle}",
        "time_max_torque": t_max_torq,
        "time_motoring":   t_motor,
        "time_max_power":  t_max_pwr,
        "time_idle":       t_idle,
    }


def decode_asc1(data):
    """PGN 0xFE6E - Air Suspension Control 1
    Byte 0: Chassis Height (Front): bits 0-1 status, bits 2-7 target
    Byte 1: Drive Axle Air Suspension Height Command (1 mm/bit, offset -127mm)
    Byte 2-3: Steer Axle Air Suspension Height (0.5 mm/bit, offset -32mm)
    Byte 4: Air Suspension Control State
    """
    if len(data) < 8:
        return None
    drive_height = f"{data[1] - 127} mm" if data[1] != 0xFF else "N/A"
    steer_raw    = data[2] | (data[3] << 8)
    steer_height = f"{steer_raw * 0.5 - 32:.1f} mm" if steer_raw != 0xFFFF else "N/A"
    ctrl_state_raw = data[4] & 0x0F
    ctrl_states  = {0: "Manual", 1: "Automatic", 2: "Kneel", 3: "High", 4: "Loading", 15: "N/A"}
    ctrl_state   = ctrl_states.get(ctrl_state_raw, f"State {ctrl_state_raw}")
    return {
        "decoded":       f"DriveHeight={drive_height}  SteerHeight={steer_height}  State={ctrl_state}",
        "drive_height":  drive_height,
        "steer_height":  steer_height,
        "ctrl_state":    ctrl_state,
    }


def decode_asc2(data):
    """PGN 0xFE6F - Air Suspension Control 2
    Byte 0: Front Axle Left Air Spring Pressure (8 kPa/bit)
    Byte 1: Front Axle Right Air Spring Pressure (8 kPa/bit)
    Byte 2: Rear Axle Left Air Spring Pressure (8 kPa/bit)
    Byte 3: Rear Axle Right Air Spring Pressure (8 kPa/bit)
    """
    if len(data) < 4:
        return None
    fl_p = f"{data[0] * 8} kPa" if data[0] != 0xFF else "N/A"
    fr_p = f"{data[1] * 8} kPa" if data[1] != 0xFF else "N/A"
    rl_p = f"{data[2] * 8} kPa" if data[2] != 0xFF else "N/A"
    rr_p = f"{data[3] * 8} kPa" if data[3] != 0xFF else "N/A"
    return {
        "decoded":    f"FL={fl_p}  FR={fr_p}  RL={rl_p}  RR={rr_p}",
        "fl_spring":  fl_p,
        "fr_spring":  fr_p,
        "rl_spring":  rl_p,
        "rr_spring":  rr_p,
    }


# ---------------------------------------------------------------------------
# J1939-73 additional DM decoders
# ---------------------------------------------------------------------------

def decode_dm4(data):
    """PGN 0xFECD - Freeze Frame Parameters (DM4)
    Same DTC structure as DM1, but captures data at time of fault.
    Bytes 0-1: Lamp status (same as DM1)
    Bytes 2+: DTC entries (4 bytes each) followed by freeze frame SPNs
    """
    if len(data) < 2:
        return None
    # Reuse DM1 lamp + DTC parsing
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM4 (FreezeFrame):")
    return result


def decode_dm9(data):
    """PGN 0xFED2 - Emission-Related Permanent DTCs (DM9)
    Same structure as DM1 -- permanent (non-clearable) emission fault codes.
    """
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM9 (Permanent):")
    return result


def decode_dm10(data):
    """PGN 0xFED3 - Emission-Related Pending DTCs 2 (DM10)
    Same structure as DM1.
    """
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM10 (EmPending2):")
    return result


def decode_dm11(data):
    """PGN 0xFED4 - Emission Diagnostic Data Clear / Reset (DM11)
    No signal content -- broadcast trigger to clear emission-related DTCs.
    """
    return {"decoded": "DM11: Clear/Reset Emission-Related Diagnostic Info"}


def decode_dm12(data):
    """PGN 0xFED5 - Emission-Related Active DTCs (DM12)
    Same structure as DM1 -- emission-specific active faults.
    """
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM12 (EmActive):")
    return result


def decode_dm13(data):
    """PGN 0xFED6 - Stop Start Broadcast (DM13)
    Byte 0: Current Data Link (bits 0-3) / Requested Data Link (bits 4-7)
    Byte 1: Hold Signal (bits 0-1)
    """
    if len(data) < 2:
        return None
    curr_link = data[0] & 0x0F
    req_link  = (data[0] >> 4) & 0x0F
    hold_raw  = data[1] & 0x03
    hold_names = {0: "Stop broadcast", 1: "Start broadcast", 2: "Error", 3: "N/A"}
    hold = hold_names.get(hold_raw, str(hold_raw))
    link_names = {0: "SAE J1939", 1: "ISO 15765-4", 2: "SAE J1708", 15: "N/A"}
    return {
        "decoded":    f"Hold={hold}  CurrLink={link_names.get(curr_link, str(curr_link))}  ReqLink={link_names.get(req_link, str(req_link))}",
        "hold_signal": hold,
        "curr_link":  link_names.get(curr_link, str(curr_link)),
        "req_link":   link_names.get(req_link, str(req_link)),
    }


def decode_dm14(data):
    """PGN 0xFED7 - Memory Access Request (DM14)
    Byte 0: Length of Requested Memory Access (bytes)
    Byte 1: Command (bits 0-3) / Level of Security Access (bits 4-7)
    Bytes 2-5: Memory Address
    Bytes 6-7: Additional data / extension
    """
    if len(data) < 6:
        return None
    length  = data[0]
    cmd_raw = data[1] & 0x0F
    cmd_names = {0: "Read", 1: "Write", 2: "Erase", 3: "Boot load", 14: "Other", 15: "N/A"}
    cmd = cmd_names.get(cmd_raw, f"Cmd {cmd_raw}")
    sec_level = (data[1] >> 4) & 0x0F
    address = data[2] | (data[3] << 8) | (data[4] << 16) | (data[5] << 24)
    return {
        "decoded":    f"Cmd={cmd}  Addr=0x{address:08X}  Len={length}  SecLvl={sec_level}",
        "command":    cmd,
        "address":    f"0x{address:08X}",
        "mem_length": str(length),
        "sec_level":  str(sec_level),
    }


def decode_dm15(data):
    """PGN 0xFED9 - Memory Access Response (DM15)
    Byte 0: Length of Memory Access (bytes)
    Byte 1: Error Indicator / EDCP Extension / Status
    Bytes 2-5: Memory Address
    """
    if len(data) < 6:
        return None
    length = data[0]
    status_raw = data[1] & 0x0F
    status_names = {0: "OK", 1: "Aborted", 2: "Error", 3: "Busy", 15: "N/A"}
    status = status_names.get(status_raw, f"Status {status_raw}")
    address = data[2] | (data[3] << 8) | (data[4] << 16) | (data[5] << 24)
    return {
        "decoded":  f"Status={status}  Addr=0x{address:08X}  Len={length}",
        "status":   status,
        "address":  f"0x{address:08X}",
        "length":   str(length),
    }


def decode_dm16(data):
    """PGN 0xFEDA - Binary Data Transfer (DM16)
    Byte 0: Number of occurrences of binary data byte
    Bytes 1-7: Binary data bytes
    """
    if len(data) < 1:
        return None
    num_bytes = data[0]
    hex_str = " ".join(f"{b:02X}" for b in data[1:min(1 + num_bytes, len(data))])
    return {
        "decoded":    f"BinaryData: [{hex_str}]  ({num_bytes} bytes)",
        "num_bytes":  str(num_bytes),
        "data_hex":   hex_str,
    }


def decode_dm22(data):
    """PGN 0xFEDC - Individual DTC Clear/Reset of Active and Previously Active DTCs (DM22)
    Byte 0: Control Byte
    Bytes 1-4: DTC (SPN + FMI as in DM1 encoding)
    """
    if len(data) < 5:
        return None
    ctrl_raw = data[0]
    ctrl_names = {0: "Clear Active DTC", 1: "Clear Previously Active DTC",
                  2: "Ack - cleared", 3: "NACK - DTC not cleared", 4: "Access Denied", 5: "Unknown DTC"}
    ctrl = ctrl_names.get(ctrl_raw, f"Ctrl {ctrl_raw}")
    b3, b4, b5 = data[1], data[2], data[3]
    cm = (data[4] >> 7) & 0x1
    oc = data[4] & 0x7F
    if cm == 0:
        spn = b3 | (b4 << 8) | ((b5 >> 5) << 16)
        fmi = b5 & 0x1F
    else:
        spn = b3 | (b4 << 8) | ((b5 & 0x07) << 16)
        fmi = (b5 >> 3) & 0x1F
    fmi_desc = FMI_DESCRIPTIONS.get(fmi, f"FMI {fmi}")
    return {
        "decoded":  f"DM22: {ctrl}  SPN{spn}/FMI{fmi}({fmi_desc})/OC={oc}",
        "control":  ctrl,
        "spn":      str(spn),
        "fmi":      str(fmi),
        "fmi_desc": fmi_desc,
        "oc":       str(oc),
    }


def decode_dm23(data):
    """PGN 0xFEDD - Emission-Related Previously Active DTCs (DM23)
    Same structure as DM1.
    """
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM23 (EmPrevActive):")
    return result


def decode_dm24(data):
    """PGN 0xFEDE - SPN Support (DM24)
    Each group of 4 bytes = one SPN entry:
      Bytes 0-2: SPN (bits 0-18) + data length (bits 19-23) + DSP (bit 24-25)
      Byte 3: SPN support bits
    Typically a long multi-packet message.
    """
    if len(data) < 4:
        return None
    num_spns = len(data) // 4
    spn_list = []
    for i in range(min(num_spns, 8)):  # show up to 8
        base = i * 4
        spn = data[base] | (data[base+1] << 8) | ((data[base+2] & 0x07) << 16)
        spn_list.append(f"SPN{spn}")
    summary = ", ".join(spn_list)
    if num_spns > 8:
        summary += f" ... (+{num_spns - 8} more)"
    return {
        "decoded":   f"DM24: {num_spns} SPNs supported  [{summary}]",
        "num_spns":  str(num_spns),
        "spn_list":  summary,
    }


def decode_dm25(data):
    """PGN 0xFEDF - Expanded Freeze Frame (DM25)
    Bytes 0-3: DTC that triggered freeze frame (same as DM1 DTC encoding)
    Bytes 4+: SPN/value pairs (variable length, TP message typical)
    """
    if len(data) < 4:
        return None
    b3, b4, b5, b6 = data[0], data[1], data[2], data[3]
    cm = (b6 >> 7) & 0x1
    oc = b6 & 0x7F
    if cm == 0:
        spn = b3 | (b4 << 8) | ((b5 >> 5) << 16)
        fmi = b5 & 0x1F
    else:
        spn = b3 | (b4 << 8) | ((b5 & 0x07) << 16)
        fmi = (b5 >> 3) & 0x1F
    fmi_desc = FMI_DESCRIPTIONS.get(fmi, f"FMI {fmi}")
    num_params = (len(data) - 4) // 4 if len(data) > 4 else 0
    return {
        "decoded":    f"DM25 FreezeFrame: SPN{spn}/FMI{fmi}({fmi_desc})  {num_params} param(s)",
        "trigger_spn": str(spn),
        "trigger_fmi": str(fmi),
        "fmi_desc":    fmi_desc,
        "num_params":  str(num_params),
    }


def decode_dm26(data):
    """PGN 0xDF00 - Diagnostic Readiness 3 (DM26)
    Byte 0: Time Since Engine Start (1 s/bit)
    Byte 1: Number of Warm-ups Since DTCs Cleared
    Bytes 2-3: Continuous Monitor System Status / Support flags
    Bytes 4-5: Once-per-Trip Monitor System Status / Support flags
    """
    if len(data) < 6:
        return None
    time_start = f"{data[0]} s" if data[0] != 0xFF else "N/A"
    warmups    = str(data[1]) if data[1] != 0xFF else "N/A"
    return {
        "decoded":    f"DM26: TimeSinceStart={time_start}  WarmupsSinceClear={warmups}",
        "time_since_start": time_start,
        "warmups":          warmups,
    }


def decode_dm27(data):
    """PGN 0xFEE1 - All Pending DTCs (DM27)
    Same structure as DM1 -- all pending faults regardless of emission relevance.
    """
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM27 (AllPending):")
    return result


def decode_dm28(data):
    """PGN 0xFEE2 - Permanent DTCs (DM28)
    Same structure as DM1 -- non-clearable permanent fault codes.
    """
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM28 (Permanent):")
    return result


def decode_dm29(data):
    """PGN 0xD300 - Regulated Exhaust Emission Levels (DM29)
    Byte 0: Emission-Related Pending DTC Count
    Byte 1: All Pending DTC Count
    Byte 2: Emission-Related MIL-On DTC Count
    Byte 3: Emission-Related Previously Active DTC Count
    Byte 4: Emission-Related Permanent DTC Count
    """
    if len(data) < 5:
        return None
    em_pend  = str(data[0]) if data[0] != 0xFF else "N/A"
    all_pend = str(data[1]) if data[1] != 0xFF else "N/A"
    mil_on   = str(data[2]) if data[2] != 0xFF else "N/A"
    prev_act = str(data[3]) if data[3] != 0xFF else "N/A"
    perm     = str(data[4]) if data[4] != 0xFF else "N/A"
    return {
        "decoded":      f"DM29: EmPending={em_pend}  AllPending={all_pend}  MIL-On={mil_on}  PrevActive={prev_act}  Permanent={perm}",
        "em_pending":   em_pend,
        "all_pending":  all_pend,
        "mil_on_count": mil_on,
        "prev_active":  prev_act,
        "permanent":    perm,
    }


def decode_dm30(data):
    """PGN 0xD400 - Scaled Test Results (DM30)
    Each 7-byte group: SPN (3 bytes) + FMI (1) + Test Value (2) + Max/Min Limit (2)
    Typically multi-packet.
    """
    if len(data) < 7:
        return None
    num_results = len(data) // 7
    results = []
    for i in range(min(num_results, 4)):
        base = i * 7
        if base + 6 >= len(data):
            break
        spn = data[base] | (data[base+1] << 8) | ((data[base+2] & 0x07) << 16)
        fmi = data[base+3] & 0x1F
        val = data[base+4] | (data[base+5] << 8)
        lim = data[base+6]
        results.append(f"SPN{spn}/FMI{fmi}=0x{val:04X}")
    summary = " | ".join(results)
    if num_results > 4:
        summary += f" (+{num_results - 4} more)"
    return {
        "decoded":     f"DM30: {num_results} result(s)  {summary}",
        "num_results": str(num_results),
        "results":     summary,
    }


def decode_dm31(data):
    """PGN 0xD500 - DTC to Lamp Association (DM31)
    Each 4-byte group: DTC (3 bytes) + Lamp status byte
    """
    if len(data) < 4:
        return None
    num_dtcs = len(data) // 4
    parts = []
    for i in range(min(num_dtcs, 4)):
        base = i * 4
        if base + 3 >= len(data):
            break
        b3, b4, b5, b6 = data[base], data[base+1], data[base+2], data[base+3]
        cm = (b6 >> 7) & 0x1
        if cm == 0:
            spn = b3 | (b4 << 8) | ((b5 >> 5) << 16)
            fmi = b5 & 0x1F
        else:
            spn = b3 | (b4 << 8) | ((b5 & 0x07) << 16)
            fmi = (b5 >> 3) & 0x1F
        mil_raw = (b6 >> 4) & 0x03
        mil = _lamp(mil_raw)
        parts.append(f"SPN{spn}/FMI{fmi} MIL={mil}")
    summary = " | ".join(parts)
    return {
        "decoded":   f"DM31: {num_dtcs} DTC-Lamp(s)  {summary}",
        "num_dtcs":  str(num_dtcs),
        "dtc_lamps": summary,
    }


def decode_dm32(data):
    """PGN 0xD600 - Regulated Exhaust Emission Level Exceedance (DM32)
    Byte 0: Exceedance Status bits
    Bytes 1-2: Exceedance Time (1 s/bit)
    """
    if len(data) < 3:
        return None
    status_raw = data[0]
    exc_time = f"{data[1] | (data[2] << 8)} s" if (data[1] | (data[2] << 8)) != 0xFFFF else "N/A"
    return {
        "decoded":    f"DM32: ExceedanceStatus=0x{status_raw:02X}  Time={exc_time}",
        "exc_status": f"0x{status_raw:02X}",
        "exc_time":   exc_time,
    }


def decode_dm33(data):
    """PGN 0xD700 - Emission Increasing AECD Active Time (DM33)
    Each 8-byte group: AECD Number (1) + Engine Hours (4, 0.05 h/bit) + Idle Hours (4)
    """
    if len(data) < 5:
        return None
    num_aecd = len(data) // 5
    parts = []
    for i in range(min(num_aecd, 3)):
        base = i * 5
        if base + 4 >= len(data):
            break
        aecd_num = data[base]
        hrs_raw = data[base+1] | (data[base+2] << 8) | (data[base+3] << 16) | (data[base+4] << 24)
        hrs = _hours(hrs_raw)
        parts.append(f"AECD{aecd_num}={hrs}")
    summary = " | ".join(parts)
    return {
        "decoded":   f"DM33: {num_aecd} AECD(s)  {summary}",
        "num_aecd":  str(num_aecd),
        "aecd_list": summary,
    }


def decode_dm34(data):
    """PGN 0xD800 - NTE (Not-to-Exceed) Status (DM34)
    Byte 0: NTE Status bits
      bits 0-1: NTE Carve Out Zone Status
      bits 2-3: NTE Control Area Status
      bits 4-5: Manufacturer-Specific NTE Override
    """
    if len(data) < 1:
        return None
    carve_out = _spn_2bit(data[0] & 0x03)
    ctrl_area = _spn_2bit((data[0] >> 2) & 0x03)
    override  = _spn_2bit((data[0] >> 4) & 0x03)
    return {
        "decoded":    f"DM34: NTE CarveOut={carve_out}  CtrlArea={ctrl_area}  Override={override}",
        "carve_out":  carve_out,
        "ctrl_area":  ctrl_area,
        "override":   override,
    }


def decode_dm35(data):
    """PGN 0xD900 - Immediate Fault Status (DM35)
    Same structure as DM1 -- faults that require immediate action.
    """
    result = decode_dm1(data)
    if result:
        result["decoded"] = result["decoded"].replace("DM1:", "DM35 (Immediate):")
    return result


def decode_dm36(data):
    """PGN 0xDA00 - DTC Counts (DM36)
    Byte 0: Active DTC Count
    Byte 1: Previously Active DTC Count
    Byte 2: Pending DTC Count
    Byte 3: Permanent DTC Count
    """
    if len(data) < 4:
        return None
    active   = str(data[0]) if data[0] != 0xFF else "N/A"
    prev     = str(data[1]) if data[1] != 0xFF else "N/A"
    pending  = str(data[2]) if data[2] != 0xFF else "N/A"
    perm     = str(data[3]) if data[3] != 0xFF else "N/A"
    return {
        "decoded":        f"DM36: Active={active}  PrevActive={prev}  Pending={pending}  Permanent={perm}",
        "active_count":   active,
        "prev_active":    prev,
        "pending_count":  pending,
        "permanent_count": perm,
    }


# ---------------------------------------------------------------------------
# Map PGN -> decoder function
# ---------------------------------------------------------------------------
PGN_DECODERS = {
    0x00F002: decode_ebc1,
    0x00F004: decode_eec1,
    0x00F005: decode_eec2,
    0x00F006: decode_eec3,
    0x00F007: decode_etc1,
    0x00F008: decode_etc2,
    0x00F00B: decode_erc1,
    0x00FEF7: decode_eflp1,
    0x00FEF1: decode_ccvs,
    0x00FEF2: decode_lfe,
    0x00FEF3: decode_amb,
    0x00FEF4: decode_ic1,
    0x00FEF5: decode_vep1,
    0x00FEF0: decode_tf,
    0x00FEEF: decode_et1,
    0x00FEEB: decode_hours,
    0x00FEE0: decode_vd,
    0x00FEE9: decode_fd,
    0x00FEFE: decode_wfi,
    0x00FECA: decode_dm1,
    0x00FECB: decode_dm2,
    0x00EE00: decode_ac,
    0x00EA00: decode_request,
    0x00E800: decode_ack,
    # --- newly added decoders ---
    0x00F003: decode_ebc2,
    0x00F009: decode_eac1,
    0x00F00A: decode_eac2,
    0x00F00C: decode_erc2,
    0x00F010: decode_eec4,
    0x00F011: decode_gfr,
    0x00F013: decode_eec5,
    0x00F034: decode_eec6,
    0x00F020: decode_gfc,
    0x00FEF6: decode_tc1,
    0x00FEF8: decode_pto,
    0x00FEF9: decode_ccss,
    0x00FEFA: decode_tire,
    0x00FEFB: decode_fsp,
    0x00FEFC: decode_ci,
    0x00FEFD: decode_ccc,
    0x00FEFF: decode_bt,
    0x00FEEE: decode_vh,
    0x00FEED: decode_io,
    0x00FEEC: decode_vi,
    0x00FECC: decode_dm3,
    0x00FECE: decode_dm5,
    0x00FECF: decode_dm6,
    0x00FED0: decode_dm7,
    0x00FED8: decode_dm8,
    0x00FEDB: decode_dm21,
    0x00FD09: decode_bmsh,
    0x00FD7D: decode_aegr1,
    0x00FDB5: decode_at1t1i,
    0x00FDB8: decode_at1psdp,
    0x00FDB9: decode_atpfdc,
    0x00FDBA: decode_at1og,
    # --- J1939-71 bug fixes ---
    0x00F014: decode_hours,    # Engine Hours EH - re-uses HOURS decoder
    # --- J1939-71 new decoders ---
    0x00FEEA: decode_tsc1,
    0x00FEE5: decode_td,
    0x00FEE3: decode_soft,
    0x00FEE4: decode_ecuh,
    0x00FEC1: decode_hrvd,
    0x00FEC2: decode_hretf,
    0x00FEC3: decode_esc,
    0x00FEB0: decode_tf2,
    0x00FEB4: decode_eflp2,
    0x00FEB5: decode_gfe,
    0x00FEB6: decode_agfe,
    0x00FEBD: decode_et2,
    0x00FEC0: decode_gfc2,
    0x00FEA8: decode_eec7,
    0x00FEA9: decode_eth,
    0x00FE6E: decode_asc1,
    0x00FE6F: decode_asc2,
    # --- J1939-73 new DM decoders ---
    0x00FECD: decode_dm4,
    0x00FED2: decode_dm9,
    0x00FED3: decode_dm10,
    0x00FED4: decode_dm11,
    0x00FED5: decode_dm12,
    0x00FED6: decode_dm13,
    0x00FED7: decode_dm14,
    0x00FED9: decode_dm15,
    0x00FEDA: decode_dm16,
    0x00FEDC: decode_dm22,
    0x00FEDD: decode_dm23,
    0x00FEDE: decode_dm24,
    0x00FEDF: decode_dm25,
    0x00DF00: decode_dm26,
    0x00FEE1: decode_dm27,
    0x00FEE2: decode_dm28,
    0x00D300: decode_dm29,
    0x00D400: decode_dm30,
    0x00D500: decode_dm31,
    0x00D600: decode_dm32,
    0x00D700: decode_dm33,
    0x00D800: decode_dm34,
    0x00D900: decode_dm35,
    0x00DA00: decode_dm36,
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
        self.packets     = {}   # seq_num (1-based) -> 7-byte payload list

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
    """J1939 High-Level Analyzer -- decodes J1939 frames from Logic 2 CAN LLA."""

    # -- Settings shown in Logic 2 UI -----------------------------------------
    show_standard_frames = ChoicesSetting(
        label="Show 11-bit (Standard) CAN Frames",
        choices=("Hide", "Show as Raw CAN")
    )

    show_tp_fragments = ChoicesSetting(
        label="Show TP Fragment Frames (TP.CM / TP.DT)",
        choices=("Hide", "Show")
    )

    # -- Output frame display templates ---------------------------------------
    # All J1939 frames use a single "j1939" type so the Data Table shows
    # one consistent column set.  The "summary" column is the primary
    # human-readable decode; remaining columns give structured data.
    result_types = {
        "j1939": {
            "format": "{{data.summary}}"
        },
    }

    def __init__(self):
        self._pending_id   = None
        self._pending_data = []
        self._pending_start = None
        self._tp_sessions  = {}  # keyed by source_address (int)

    # -- Internal helpers ------------------------------------------------------

    def _sa_name(self, sa):
        return SA_NAMES.get(sa, f"SA 0x{sa:02X}")

    def _pgn_name(self, pgn):
        return PGN_NAMES.get(pgn, f"PGN 0x{pgn:04X}")

    def _decode_j1939_id(self, can_id):
        """Unpack 29-bit J1939 CAN ID -> (priority, pgn, da, sa)"""
        priority = (can_id >> 26) & 0x07
        dp       = (can_id >> 24) & 0x01
        pf       = (can_id >> 16) & 0xFF
        ps       = (can_id >>  8) & 0xFF
        sa       = (can_id >>  0) & 0xFF

        if pf < 0xF0:
            # PDU1 -- peer-to-peer: PS = destination address, PGN has PS=0
            da  = ps
            pgn = (dp << 17) | (pf << 8)
        else:
            # PDU2 -- broadcast: PS is part of PGN
            da  = 0xFF  # Global
            pgn = (dp << 17) | (pf << 8) | ps

        return priority, pgn, da, sa


    def _emit(self, start_time, end_time, fields):
        """Emit a single 'j1939' AnalyzerFrame with a guaranteed base column set.

        Every frame always includes: summary, pgn, pgn_name, priority, from, to,
        raw_bytes, and decoded.  Signal-specific columns are passed in via fields
        and merged on top of the base.  This ensures the Data Table shows a clean,
        consistent column layout.
        """
        base = {
            "summary":   "",
            "pgn":       "",
            "pgn_name":  "",
            "priority":  "",
            "from":      "",
            "to":        "",
            "raw_bytes": "",
            "decoded":   "",
        }
        base.update(fields)
        return AnalyzerFrame("j1939", start_time, end_time, base)

    def _process_complete_frame(self, can_id, data, start_time, end_time, is_extended):
        """Decode one complete CAN frame and return an AnalyzerFrame (or None)."""

        if not is_extended:
            # 11-bit standard frame -- not J1939
            if self.show_standard_frames == "Show as Raw CAN":
                hex_str = " ".join(f"{b:02X}" for b in data)
                return self._emit(start_time, end_time, {
                    "summary":  f"STD CAN 0x{can_id:03X} [{hex_str}]",
                    "pgn":      f"0x{can_id:03X}",
                    "pgn_name": "Standard CAN (non-J1939)",
                    "raw_bytes": hex_str,
                })
            return None

        priority, pgn, da, sa = self._decode_j1939_id(can_id)
        pgn_name = self._pgn_name(pgn)
        sa_name  = self._sa_name(sa)
        da_name  = self._sa_name(da) if da != 0xFF else "Broadcast"
        hex_str  = " ".join(f"{b:02X}" for b in data)

        # -- Transport Protocol handling -----------------------------------
        is_tp_cm = (pgn & 0x00FF00) == 0x00EC00
        is_tp_dt = (pgn & 0x00FF00) == 0x00EB00

        if is_tp_cm and len(data) == 8:
            ctrl = data[0]
            if ctrl == 0x20:  # BAM
                total_bytes  = data[1] | (data[2] << 8)
                num_packets  = data[3]
                tp_pgn       = data[5] | (data[6] << 8) | (data[7] << 16)
                self._tp_sessions[sa] = _TPSession(tp_pgn, total_bytes, num_packets, start_time)
                if self.show_tp_fragments == "Show":
                    tp_pgn_name = self._pgn_name(tp_pgn)
                    summary = f"[TP.BAM] {tp_pgn_name} from {sa_name} ({total_bytes}B / {num_packets} pkts)"
                    return self._emit(start_time, end_time, {
                        "summary":   summary,
                        "pgn":       f"0x{tp_pgn:04X}",
                        "pgn_name":  f"[TP.BAM] {tp_pgn_name}",
                        "priority":  str(priority),
                        "from":      sa_name,
                        "to":        da_name,
                        "raw_bytes": hex_str,
                        "decoded":   f"BAM announce: {total_bytes}B in {num_packets} packets",
                    })
                return None

        if is_tp_dt and len(data) == 8:
            seq     = data[0]
            payload = list(data[1:8])
            session = self._tp_sessions.get(sa)
            if session:
                session.add_packet(seq, payload)
                if session.is_complete():
                    reassembled  = session.reassemble()
                    tp_pgn       = session.pgn
                    tp_pgn_name  = self._pgn_name(tp_pgn)
                    decoder      = PGN_DECODERS.get(tp_pgn)
                    sig          = decoder(reassembled) if decoder else None
                    decoded_str  = sig["decoded"] if sig else ""
                    full_hex     = " ".join(f"{b:02X}" for b in reassembled)
                    summary      = (f"[TP] {tp_pgn_name} from {sa_name} | {decoded_str}"
                                    if decoded_str
                                    else f"[TP] {tp_pgn_name} from {sa_name} | [{full_hex}]")
                    # Build signal columns, stripping the internal 'decoded' key
                    sig_cols = {k: v for k, v in (sig or {}).items() if k != "decoded"}
                    result = self._emit(session.start_time, end_time, {
                        "summary":   summary,
                        "pgn":       f"0x{tp_pgn:04X}",
                        "pgn_name":  f"[TP] {tp_pgn_name}",
                        "priority":  str(priority),
                        "from":      sa_name,
                        "to":        da_name,
                        "raw_bytes": full_hex,
                        "decoded":   decoded_str,
                        **sig_cols,
                    })
                    del self._tp_sessions[sa]
                    return result
                else:
                    if self.show_tp_fragments == "Show":
                        summary = f"[TP.DT] pkt#{seq} from {sa_name}"
                        return self._emit(start_time, end_time, {
                            "summary":   summary,
                            "pgn":       f"0x{pgn:04X}",
                            "pgn_name":  "[TP.DT]",
                            "priority":  str(priority),
                            "from":      sa_name,
                            "to":        da_name,
                            "raw_bytes": hex_str,
                            "decoded":   f"Packet {seq}",
                        })
                    return None
            return None

        # -- Normal single-frame message -----------------------------------
        decoder = PGN_DECODERS.get(pgn)
        sig     = decoder(data) if decoder else None
        decoded_str = sig["decoded"] if sig else ""
        sig_cols    = {k: v for k, v in (sig or {}).items() if k != "decoded"}

        summary = (f"{pgn_name} from {sa_name} | {decoded_str}"
                   if decoded_str
                   else f"{pgn_name} from {sa_name} | [{hex_str}]")

        return self._emit(start_time, end_time, {
            "summary":   summary,
            "pgn":       f"0x{pgn:04X}",
            "pgn_name":  pgn_name,
            "priority":  str(priority),
            "from":      sa_name,
            "to":        da_name,
            "raw_bytes": hex_str,
            "decoded":   decoded_str,
            **sig_cols,
        })

    # -- Main HLA entry point --------------------------------------------------

    def decode(self, frame: AnalyzerFrame):
        """
        Called once per frame from the CAN low-level analyzer.

        The CAN LLA emits frames with these types:
          identifier_field  ->  frame.data['identifier'] (int), frame.data.get('extended') (bool)
          data_field        ->  frame.data['data'] (bytes, 1 byte per call)
          crc_field         ->  frame.data['crc'] (int) -- marks end of frame
          error_field       ->  indicates a CAN error
        """
        ft = frame.type

        if ft == "identifier_field":
            # Start of a new CAN frame -- reset accumulator
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
            # Frame complete -- decode it
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
            return self._emit(frame.start_time, frame.end_time, {
                "summary":   "CAN error frame",
                "pgn_name":  "CAN Error",
                "decoded":   "CAN bus error detected",
            })

        return None
