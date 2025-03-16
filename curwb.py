"""
curwb.py
David Rice

A library for decoding Cisco URWB telemetry packets - version 2.0.19
"""

from scapy.all import *

"""
Enumerate all available TLVs
"""
TLVClasses = {
   0x0001: "FHCTRL_VEHICLE_TLV",
   0x000a: "TITAN_TLV",
   0x000d: "ETH_TPT_TLV",
   0x001b: "MULTIPATH_TLV",
   0x001d: "FHCTRL_VEHICLE_MULTI_RADIO_TLV",
   0x001e: "TX_STATS_MULTI_RADIO_TLV",
   0x001f: "RX_STATS_MULTI_RADIO_TLV",
   0x0021: "HANDOFF_TBL_MUTLI_RADIO_TLV",
   0x0022: "AGGR_TRAFFIC_MULTI_RADIO_TLV",
   0x0023: "RADIO_CFG_MULTI_RADIO_TLV",
   0x0024: "MPO_EXT_TLV",
   0x0025: "HANDOFF_TBL_MULTI_RADIO_MPO_TLV",
   0x0026: "BLOCKLIST_MULTI_RADIO_TLV",
   0x0027: "GNSS_NMEA_TLV"
}

def guessTLVClass(packet, **kargs):
   """
   Determine TLV type from first 2 bytes
   TODO: Currently defaults to GNSS_NMEA_TLV if no match, probably need to handle that differently
   """
   tlvNumber = raw(packet)[0:2]
   clsName = TLVClasses.get(int.from_bytes(tlvNumber, byteorder='big'), "GNSS_NMEA_TLV")
   cls = globals()[clsName]
   return cls(packet, **kargs)

class TLVListField(PacketListField):
   """
   Custom PacketListField class for a diverse set of TLVs
   """
   def __init__(self):
      PacketListField.__init__(
         self,
         "TLVS",
         [],
         guessTLVClass,
      )

class URWBTelemetry(Packet):
    """
    Custom Packet class for the Cisco URWB telemetry header
    TODO: Handle TS_REF differently as it is currently divided into two different variables seconds and microseconds
    TODO: Decode FLAGS bits
    """
    name = "URWB Telemetry"
    fields_desc = [
        BitField("MAGIC_NUM", None, 32),
        BitField("FLAGS", None, 32),
        IPField("MESH_ID", None),
        BitField("VEHICLE_ID", None, 32),
        IPField("MESHEND_ID", None),
        BitField("SEQ", None, 32),
        BitField("TS_REF_SEC", None, 32),
        BitField("TS_REF_USEC", None, 32),
        TLVListField()
    ]

class FHCTRL_ENTRY(Packet):
   """
   Custom Packet class for fhctrl entries in the FHCTRL_VEHICLE_TLV and the FHCTRL_VEHICLE_MULTI_RADIO_TLV
   TODO: Decode DOP bits, CHAN_INFO bits and FLAGS bits
   """
   name = "FHCTRL_ENTRY"
   fields_desc = [
     IPField("SBR_ID", None),
     IPField("MBR_ID", None),
     BitField("DOP", None, 32),
     BitField("CHAN_INFO", None, 16),
     BitField("AGE", None, 16),
     BitField("RSSI", None, 8),
     BitField("FLAGS", None, 8)
   ]
   def extract_padding(self, s):
    return "", s

class FHCTRL_VEHICLE_TLV(Packet):
   """
   Custom Packet class for the FHCTRL_VEHICLE TLV (Type: 0x001)
   TODO: Handle HO_TIME differently as it is currently divided into two different variables seconds and microseconds
   TODO: Decode HO_FLAGS bits, DOP bits and FLAGS bits
   """
   name = "FHCTRL_VEHICLE__TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     IPField("CURR_SBR", None),
     IPField("CURR_MBR", None),
     BitField("CURR_SEQ", None, 32),
     BitField("HO_TIME_sec", None, 32),
     BitField("HO_TIME_usec", None, 32),
     BitField("HO_RETRIES", None, 8),
     BitField("HO_FLAGS", None, 8),
     BitField("HO_AGE", None, 32),
     BitField("DOP", None, 32),
     BitField("FLAGS", None, 16),
     BitField("INHIBIT", None, 16),
     PacketListField("FHCTRL_ENTRIES", FHCTRL_ENTRY(), FHCTRL_ENTRY, count_from=lambda pkt:(pkt.LENGTH-34)/18)
   ]
   def extract_padding(self, s):
    return "", s

class TITAN_TLV(Packet):
   """
   Custom Packet class for the TITAN TLV (Type: 0x00A)
   TODO: Handle TIMESTAMP differently as it is currently divided into two different variables seconds and microseconds
   TODO: Decode TITAN_TYPE bits, FLAGS bits
   """
   name = "TITAN_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     BitField("TITAN_TYPE", None, 8),
     BitField("FLAGS", None, 8),
     BitField("TIMESTAMP_SEC", None, 32),
     BitField("TIMESTAMP_USEC", None, 32),
     BitField("COUNT", None, 32),
     IPField("MASTER", None),
     IPField("BACKUP", None)
   ]
   def extract_padding(self, s):
     return "", s

class ETH_ENTRY(Packet):
   """
   Custom Packet class for the ETH_ENTRY structure (part of the ETH_TPT TLV)
   """
   name = "ETH_ENTRY"
   fields_desc = [
     IPField("SRC_IP", None),
     IPField("DST_IP", None),
     BitField("TPT", None, 32),
     BitField("PKTS", None, 32)
   ]
   def extract_padding(self, s):
    return "", s

class ETH_TPT_TLV(Packet):
   """
   Custom Packet class for the ETH_TPT TLV (Type: 0x00D)
   """
   name = "ETH_TPT_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     BitField("NUM_TX", None, 16),
     PacketListField("ETH_ENTRIES", ETH_ENTRY(), ETH_ENTRY, count_from=lambda pkt:(pkt.LENGTH-2)/16)
   ]
   def extract_padding(self, s):
     return "", s

class MULTIPATH_TLV(Packet):
   """
   Custom Packet class for the MULTIPATH_TLV (Type: 0x01B)
   TODO: Decode FLAGS bits and PEERS bits
   """
   name = "MULTIPATH_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     BitField("FLAGS", None, 8),
     BitField("NUM_PEERS", None, 8),
     FieldListField("PEERS", None, BitField("PEER", None, 32), count_from=lambda pkt:pkt.NUM_PEERS)
   ]
   def extract_padding(self, s):
     return "", s

class FHCTRL_VEHICLE_MULTI_RADIO_TLV(Packet):
   """
   Custom Packet class for the FHCTRL_VEHICLE_MULTI_RADIO TLV (Type: 0x01D)
   TODO: Handle HO_TIME differently as it is currently divided into two different variables seconds and microseconds
   TODO: Decode HO_FLAGS bits, DOP bits and FLAGS bits
   """
   name = "FHCTRL_VEHICLE_MULTI_RADIO_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     IPField("CURR_SBR", None),
     IPField("CURR_MBR", None),
     BitField("CURR_SEQ", None, 32),
     BitField("HO_TIME_sec", None, 32),
     BitField("HO_TIME_usec", None, 32),
     BitField("HO_RETRIES", None, 8),
     BitField("HO_FLAGS", None, 8),
     BitField("HO_AGE", None, 32),
     BitField("DOP", None, 32),
     BitField("FLAGS", None, 16),
     BitField("INHIBIT", None, 16),
     PacketListField("FHCTRL_ENTRIES", FHCTRL_ENTRY(), FHCTRL_ENTRY, count_from=lambda pkt:(pkt.LENGTH-34)/18)
   ]
   def extract_padding(self, s):
    return "", s

class TX_STAT(Packet):
   """
   Custom Packet class for the TX_STATS structure (part of the TX_STATS_MULTI_RADIO TLV)
   TODO: Decode TX_FLAGS bits and TX_MCS bits
   """
   name = "TX_STAT"
   fields_desc = [
     IPField("SRC_IP", None),
     IPField("DST_IP", None),
     BitField("SENT", None, 32),
     BitField("RETRIES", None, 32),
     BitField("FAILED", None, 32),
     BitField("BYTES", None, 32),
     BitField("AGE", None, 16),
     BitField("TX_FLAGS", None, 8),
     BitField("TX_MCS", None, 8)
   ]
   def extract_padding(self, s):
    return "", s

class TX_STATS_MULTI_RADIO_TLV(Packet):
   """
   Custom Packet class for the TX_STATS_MULTI_RADIO TLV (Type: 0x01E)
   """
   name = "TX_STATS_MULTI_RADIO_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     PacketListField("TX_STATS", TX_STAT(), TX_STAT, count_from=lambda pkt:pkt.LENGTH/28)
   ]
   def extract_padding(self, s):
    return "", s

class RX_STA(Packet):
   """
   Custom Packet class for the RX_STA structure (part of the RX_STATS_MULTI_RADIO TLV)
   TODO: Decode RX_MCS bits and RX_FLAGS bits
   """
   name = "RX_STA"
   fields_desc = [
     IPField("SRC_IP", None),
     IPField("DST_IP", None),
     BitField("RECEIVED", None, 32),
     BitField("BYTES", None, 32),
     BitField("RSSI", None, 8),
     BitField("RX_MCS", None, 8),
     BitField("RX_FLAGS", None, 8),
     BitField("RESERVED_1", None, 8),
     BitField("AGE", None, 16)
   ]
   def extract_padding(self, s):
    return "", s

class RX_STATS_MULTI_RADIO_TLV(Packet):
   """
   Custom Packet class for the RX_STATS_MULTI_RADIO TLV (Value: 0x01F)
   """
   name = "RX_STATS_MULTI_RADIO_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     PacketListField("RX_STATS", RX_STA(), RX_STA, count_from=lambda pkt:pkt.LENGTH/22)
   ]
   def extract_padding(self, s):
    return "", s

class HANDOFF_TBL_MUTLI_RADIO_TLV(Packet):
   """
   Custom Packet class for the HANDOFF_TBL_MULTI_RADIO TLV (Type: 0x021)
   TODO: Validate that UNITS is NUM_UNITS long
   """
   name = "HANDOFF_TBL_MUTLI_RADIO_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     IPField("SBR", None),
     IPField("MBR", None),
     IPField("MASTER", None),
     BitField("VEHICLE_ID", None, 32),
     BitField("HO_SEQ", None, 32),
     BitField("AGE", None, 32),
     BitField("RESERVED", None, 8),
     BitField("NUM_UNITS", None, 8),
     FieldListField("UNITS", None, IPField("UNIT", None), count_from=lambda pkt:pkt.NUM_UNITS)
   ]
   def extract_padding(self, s):
    return "", s

class AGGR_WLAN_TRAFF(Packet):
   """
   Custom Packet class for the aggr_wlan_raff structure (part of the AGGR_TRAFFIC_MULTI_RADIO TLV)
   """
   name = "AGGR_WLAN_TRAFF"
   fields_desc = [
     BitField("RX_WLAN", None, 32),
     BitField("TX_WLAN", None, 32),
     BitField("AVAILABLE_CAPACITY", None, 32)
   ]
   def extract_padding(self, s):
    return "", s

class AGGR_TRAFFIC_MULTI_RADIO_TLV(Packet):
   """
   Custom Packet class for the AGGR_TRAFFIC_MULTI_RADIO TLV (Type: 0x022)
   """
   name = "AGGR_TRAFFIC_MULTI_RADIO_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     BitField("RX_LAN", None, 32),
     BitField("TX_LAN", None, 32),
     PacketListField("AGGR_WLAN_TRAFFIC_STRUCTS", AGGR_WLAN_TRAFF(), AGGR_WLAN_TRAFF, count_from=lambda pkt:(pkt.LENGTH-8)/12)
   ]
   def extract_padding(self, s):
    return "", s

class RADIO_CFG(Packet):
   """
   Custom Packet class for the multi_radio_cfg_tlv structure (part of the RADIO_CFG_MULTI_RADIO TLV)
   TODO: Decode DEVINFO bits, MODE bits, STATUS bits, CWIDTH bits, FREQ1 bits, FREQ2 bits
   """
   name = "RADIO_CFG"
   fields_desc = [
     BitField("DEVINFO", None, 8),
     BitField("MODE", None, 8),
     MACField("WMAC", None),
     BitField("STATUS", None, 8),
     BitField("TXPWR", None, 8),   #represents signed 8 bit integer
     BitField("CWIDTH", None, 16),
     BitField("FREQ1", None, 32),
     BitField("FREQ2", None, 32)
   ]
   def extract_padding(self, s):
    return "", s

class RADIO_CFG_MULTI_RADIO_TLV(Packet):
   """
   Custom Packet class for the RADIO_CFG_MULTI_RADIO TLV (Type 0x023)
   """
   name = "RADIO_CFG_MULTI_RADIO_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     PacketListField("RADIO_CFGS", RADIO_CFG(), RADIO_CFG, count_from=lambda pkt:pkt.LENGTH/20)
   ]
   def extract_padding(self, s):
    return "", s

class MPO_EXT_STATE(Packet):
   """
   Custom Packet class for the mpoext_state (aka urw_client_entry?) structure (part of the MPO EXT TLV)
   TODO: Determine if mpoext_state = urw_client_entry
   """
   name = "MPO_EXT_STATE"
   fields_desc = [
     MACField("SRC_MAC", None),
     BitField("TX1", None, 32),
     BitField("TX2", None, 32),
     BitField("R1_ACCEPTED", None, 32),
     BitField("R1_DROP", None, 32),
     BitField("R2_ACCEPTED", None, 32),
     BitField("R2_DROP", None, 32),
     BitField("LOST", None, 32),
     BitField("LOST1", None, 32)
   ]
   def extract_padding(self, s):
    return "", s

class MPO_EXT_TLV(Packet):
   """
   Custom Packet class for the MPO EXT TLV (Type: 0x024)
   """
   name = "MPO_EXT_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     PacketListField("MPO_EXT_STATES", MPO_EXT_STATE(), MPO_EXT_STATE, count_from=lambda pkt:pkt.LENGTH/38)
   ]
   def extract_padding(self, s):
    return "", s

class L3HANDOFF(Packet):
   """
   Custom Packet class for the L3Handoff structure (part of the HANDOFF_TBL_MULTI_RADIO_MPO TLV)
   TODO: Decode URW_FLAGS bits
   """
   name = "L3HANDOFF"
   fields_desc = [
     IPField("SBR", None),
     IPField("MBR", None),
     IPField("MASTER", None),
     BitField("VEHICLE_ID", None, 32),
     BitField("HO_SEQ", None, 32),
     BitField("AGE", None, 32),
     BitField("URW_FLAGS", None, 8),
     BitField("NUM_UNITS", None, 8),
     FieldListField("UNITS", None, IPField("UNIT", None), count_from=lambda pkt:pkt.NUM_UNITS)
   ]
   def extract_padding(self, s):
    return "", s

class HANDOFF_TBL_MUTLI_RADIO_TLV(Packet):
   """
   Custom Packet class for the HANDOFF_TBL_MULTI_RADIO TLV (Type: 0x025)
   """
   name = "HANDOFF_TBL_MUTLI_RADIO_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     PacketListField("L3HANDOFFS", L3HANDOFF(), L3HANDOFF, length_from=lambda pkt:pkt.LENGTH)
   ]
   def extract_padding(self, s):
    return "", s

class BLOCKED_RADIO(Packet):
   """
   Custom Packet class for the multi-radio blacklist structure (part of the BLOCKLIST MULTI-RADIO TLV)
   TODO: Deocde the EXPIRY bits
   Reason Codes:
   0 - UNSPECIFIED (Not available or generic ban type)
   1 - FASTDROP (Wireless fast-drop feature)
   2 - POLEBAN (Pole-proximity / pole-ban feature)
   3 - RSSIBAN (RSSI ban feature)
   4 - HO_FAIL (Handoff failures ban)
   5 - HO_REJ (Handoff rejected ban)
   """
   name = "BLOCKED_RADIO"
   fields_desc = [
     IPField("LOCAL_IF", None),
     IPField("REMOTE_IF", None),
     BitField("EXPIRY", None, 32)
   ]
   def extract_padding(self, s):
    return "", s

class BLOCKLIST_MULTI_RADIO_TLV(Packet):
   """
   Custom Packet class for the BLOCKLIST MULTI-RADIO TLV (Type 0x026)
   """
   name = "BLOCKLIST_MULTI_RADIO_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     PacketListField("BLOCKED_RADIOS", BLOCKED_RADIO(), BLOCKED_RADIO, count_from=lambda pkt:pkt.LENGTH/12)          
   ]
   def extract_padding(self, s):
    return "", s

class GNSS_NMEA_TLV(Packet):
   """
   Custom Packet class for the GNSS_NMEA TLV (Type: 0x027)
   """
   name = "GNSS_NMEA_TLV"
   fields_desc = [
     BitField("TYPE", None, 16),
     BitField("LENGTH", None, 16),
     StrField("NMEA_STR", None)
   ]
   def extract_padding(self, s):
    return "", s
