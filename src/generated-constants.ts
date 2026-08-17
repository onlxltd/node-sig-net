//==============================================================================
// Sig-Net Protocol Framework - Constants and Definitions
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//==============================================================================
// Author:       Wayne Howell
// Date:         March 28, 2026
// Description:  Protocol constants, CoAP option numbers, TIDs, error codes,
//               and configuration parameters for Sig-Net implementation.
//               Values derived from Sig-Net Protocol Framework spec.
//==============================================================================

//------------------------------------------------------------------------------
// CoAP Protocol Constants (RFC 7252)
//------------------------------------------------------------------------------

// CoAP Version
export const COAP_VERSION = 1

// CoAP Message Types
export const COAP_TYPE_CON = 0 // Confirmable
export const COAP_TYPE_NON = 1 // Non-confirmable (used by Sig-Net)
export const COAP_TYPE_ACK = 2 // Acknowledgement
export const COAP_TYPE_RST = 3 // Reset

// CoAP Method Codes
export const COAP_CODE_EMPTY = 0x00
export const COAP_CODE_GET = 0x01
export const COAP_CODE_POST = 0x02 // Used by Sig-Net
export const COAP_CODE_PUT = 0x03
export const COAP_CODE_DELETE = 0x04

// CoAP Standard Option Numbers
export const COAP_OPTION_URI_PATH = 11

// CoAP option extended encoding constants (RFC 7252)
export const COAP_OPTION_INLINE_MAX = 12 // 0..12 encoded directly in nibble
export const COAP_OPTION_EXT8_NIBBLE = 13 // 8-bit extended follows
export const COAP_OPTION_EXT16_NIBBLE = 14 // 16-bit extended follows
export const COAP_OPTION_EXT8_BASE = 13 // value = ext + 13
export const COAP_OPTION_EXT16_BASE = 269 // value = ext + 269

// CoAP Payload Marker
export const COAP_PAYLOAD_MARKER = 0xFF

//------------------------------------------------------------------------------
// Sig-Net Custom CoAP Options (Private Use Range 2048-64999)
// These are Elective, Safe-to-Forward, NoCacheKey options
//------------------------------------------------------------------------------

export const SIGNET_OPTION_SECURITY_MODE = 2076 // 1 byte
export const SIGNET_OPTION_SENDER_ID = 2108 // 8 bytes (TUID + endpoint)
export const SIGNET_OPTION_MFG_CODE = 2140 // 2 bytes (ESTA Manufacturer ID)
export const SIGNET_OPTION_SESSION_ID = 2172 // 4 bytes (boot counter)
export const SIGNET_OPTION_SEQ_NUM = 2204 // 4 bytes (sequence number)
export const SIGNET_OPTION_HMAC = 2236 // 32 bytes (HMAC-SHA256)

//------------------------------------------------------------------------------
// Sig-Net Security Modes
//------------------------------------------------------------------------------

export const SECURITY_MODE_HMAC_SHA256 = 0x00 // HMAC-SHA256, plaintext payload
export const SECURITY_MODE_OPEN = 0x01 // Open mode, unauthenticated
export const SECURITY_MODE_UNPROVISIONED = 0xFF // Unprovisioned beacon mode

//------------------------------------------------------------------------------
// Sig-Net Type ID (TID) Definitions - Application Layer (Section 11)
// 16-bit big-endian. Upper byte = category, lower byte = subtype.
// Standard TIDs: 0x0000-0x7FFF. Manufacturer TIDs: 0x8000-0xFFFF.
// TLV total size = Length + 4 bytes (2-byte TID + 2-byte Length field).
//------------------------------------------------------------------------------

// Section 11.1 - Node-Discovery Type Identifiers
export const TID_POLL = 0x0001 // Poll: request node-discovery replies (25 bytes)
export const TID_POLL_REPLY = 0x0002 // Poll reply: presence, TUID, SoemCode, CHANGE_COUNT (12 bytes)
export const TID_SET_REPLY = 0x0003 // Set reply: trailing confirmation TLV, Flags + CHANGE_COUNT (3 bytes)

// Section 11.2 - Sender Type Identifiers
export const TID_LEVEL = 0x0101 // DMX level data, zero start code (1-512 bytes)
export const TID_PRIORITY = 0x0102 // Per-slot priority per E1.31-1 (1-512 bytes, 0-200)
export const TID_SYNC = 0x0201 // Synchronisation trigger - flush all buffers (0 bytes)
export const TID_TIMECODE = 0x0202 // MIDI-style timecode: HH MM SS FF Type (5 bytes)

// Section 11.3 - RDM Type Identifiers
export const TID_RDM_COMMAND = 0x0301 // Encapsulated E1.20 RDM request from Manager (26-257 bytes)
export const TID_RDM_RESPONSE = 0x0302 // Encapsulated E1.20 RDM response from Node (26-257 bytes)
export const TID_RDM_TOD_CONTROL = 0x0303 // TOD control: force discovery or flush (1 byte)
export const TID_RDM_TOD_DATA = 0x0304 // RDM ToD block with packet index/total + UID array (2+N bytes)
export const TID_RDM_PORT_CONFIG = 0x0305 // Enable/disable background RDM discovery (0/1 byte)
export const TID_RDM_EP_CONFIG = 0x0305 // Spec name alias for TID_RDM_PORT_CONFIG
export const TID_RDM_FLOW_CONTROL = 0x0306 // RDM FIFO capacity/availability report (0/2 bytes)

// Section 11.4 - Provisioning Type Identifiers (Root Endpoint only)
export const TID_RT_UNPROVISION = 0x0401 // Wipe keys and return to unprovisioned state (4 bytes, magic 0x57495045)
export const TID_RT_OFFBOARD = 0x0401 // Spec name alias for TID_RT_UNPROVISION

// Section 11.5 - Network Configuration Type Identifiers (Root Endpoint only)
export const TID_NW_MAC_ADDRESS = 0x0501 // Physical MAC address (0/6 bytes)
export const TID_NW_IPV4_MODE = 0x0502 // IPv4 mode: 0x00=Static, 0x01=DHCP (0/1 byte)
export const TID_NW_IPV4_ADDRESS = 0x0503 // Static IPv4 address (0/4 bytes)
export const TID_NW_IPV4_NETMASK = 0x0504 // Static IPv4 subnet mask (0/4 bytes)
export const TID_NW_IPV4_GATEWAY = 0x0505 // Static IPv4 default gateway (0/4 bytes)
export const TID_NW_IPV4_CURRENT = 0x0506 // Active IPv4 address+mask+gateway (0/12 bytes)
export const TID_NW_IPV6_MODE = 0x0581 // IPv6 mode: 0x00=Static, 0x01=SLAAC, 0x02=DHCPv6 (0/1 byte)
export const TID_NW_IPV6_ADDRESS = 0x0582 // Static IPv6 address (0/16 bytes)
export const TID_NW_IPV6_PREFIX = 0x0583 // Static IPv6 prefix length 0-128 (0/1 byte)
export const TID_NW_IPV6_GATEWAY = 0x0584 // Static IPv6 default gateway (0/16 bytes)
export const TID_NW_IPV6_CURRENT = 0x0585 // Active IPv6 address+prefix+gateway (0/33 bytes)

// Section 11.6 - Root Endpoint Type Identifiers (Root Endpoint only)
export const TID_RT_SUPPORTED_TIDS = 0x0601 // Array of supported TIDs (multiples of 2 bytes)
export const TID_RT_ENDPOINT_COUNT = 0x0602 // Total data endpoint count, not incl. EP0 (0/2 bytes)
export const TID_RT_PROTOCOL_VERSION = 0x0603 // Supported Sig-Net major version (0/1 byte)
export const TID_RT_FIRMWARE_VERSION = 0x0604 // Machine version ID + UTF-8 string (0/4-68 bytes)
export const TID_RT_DEVICE_LABEL = 0x0605 // Human-readable device label, UTF-8 (0-64 bytes)
export const TID_RT_MULT = 0x0606 // Multicast routing state: 0x00=Default, 0x01=Custom (0/1 byte)
export const TID_RT_MULT_OVERRIDE = 0x0606 // Alias: v0.15 section 11.6.6 name for TID_RT_MULT
export const TID_RT_IDENTIFY = 0x0607 // Identify state: 0x00=Off, 0x01=On (0/1 byte)
export const TID_RT_STATUS = 0x0608 // Device health bitfield: Bit0=HW Fault, Bit1=Factory, Bit2=Locked (0/4 bytes)
export const TID_RT_ROLE_CAPABILITY = 0x0609 // Role bitfield: Bit0=Node, Bit1=Sender, Bit2=Manager (0/1 byte)
export const TID_RT_REBOOT = 0x060A // Reboot command with BOOT magic (5 bytes)
export const TID_RT_MODEL_NAME = 0x060B // Product model UTF-8 string, max 64 bytes (0/1-64 bytes)
export const TID_RT_SCOPE = 0x060C // Operational URI scope UTF-8 string, max 32 bytes (0/1-32 bytes)
export const TID_RT_OTW_CAPABILITY = 0x060D // OTW onboarding capability (0/3 bytes)

// Section 11.7 - Data Endpoint Type Identifiers (Data Endpoints 1-N only)
export const TID_EP_UNIVERSE = 0x0901 // Assigned universe 1-63999, 0=unset (0/2 bytes)
export const TID_EP_LABEL = 0x0902 // Endpoint label, UTF-8, max 64 bytes, not null-terminated (0-64 bytes)
export const TID_EP_MULT_OVERRIDE = 0x0903 // Custom multicast IPv4 override, 0.0.0.0=clear (0/4 bytes)
export const TID_EP_CAPABILITY = 0x0904 // Port capabilities bitfield: Bit0=ConsumeLevel, Bit1=SupplyLevel, Bit2=ConsumeRDM, Bit3=SupplyRDM, Bit4=Virtual (0/1 byte) [v0.15 name]
export const TID_EP_DIRECTION_CAPABILITY = 0x0904 // Legacy alias for TID_EP_CAPABILITY (pre-v0.15 name)
export const TID_EP_DIRECTION = 0x0905 // Port direction: 0x00=Disabled, 0x01=Consumer, 0x02=Supplier (0/1 byte)
export const TID_EP_INPUT_PRIORITY = 0x0906 // Per-slot E1.31-1 priority for input port (0/1-512 bytes)
export const TID_EP_STATUS = 0x0907 // Endpoint health bitfield: Bit0=Activity, Bit1=HW Fault, Bit2=Locked (0/4 bytes)
export const TID_EP_FAILOVER = 0x0908 // Endpoint stream-loss failover mode + optional scene (0/3 bytes)
export const TID_EP_DMX_TIMING = 0x0909 // Endpoint DMX transmission mode and timing (0/2 bytes)
export const TID_EP_REFRESH_CAPABILITY = 0x090A // Endpoint max refresh capability in Hz (0/1 byte)
export const TID_EP_PROTOCOL = 0x090B // Endpoint active input protocol (0/1 byte)
export const TID_EP_IDENTIFY = 0x090C // Endpoint identify state (0/1 byte)

// Additional sender/control identifiers
export const TID_OSC = 0x0204 // OSC payload wrapper (variable)

// Section 11.8 - Diagnostic Type Identifiers
export const TID_DG_SECURITY_EVENT = 0xFF01 // Security event report: EventCode+Counter+SourceIP (0/11-23 bytes)
export const TID_DG_MESSAGE = 0xFF02 // Human-readable diagnostic message, UTF-8, not null-terminated (0-64 bytes)
export const TID_DG_LEVEL_FOLDBACK = 0xFF03 // Copy of level buffer for the specified universe (0/1-512 bytes)

// Poll query levels (Section 11.9)
export const QUERY_HEARTBEAT = 0x00
export const QUERY_CONFIG = 0x01
export const QUERY_FULL = 0x02
export const QUERY_EXTENDED = 0x03

// Broadcast endpoint: a poll/GET/SET addressed to 0xFFFF targets every
// applicable endpoint on the node (Section 10.2.3).
export const BROADCAST_ENDPOINT = 0xFFFF

//------------------------------------------------------------------------------
// Network Configuration
//------------------------------------------------------------------------------

export const SIGNET_UDP_PORT = 5683 // Standard CoAP port

// Multicast address range: 239.254.0.1 - 239.254.0.109
export const MULTICAST_BASE_OCTET_0 = 239
export const MULTICAST_BASE_OCTET_1 = 254
export const MULTICAST_BASE_OCTET_2 = 0
export const MULTICAST_MIN_INDEX = 1
export const MULTICAST_MAX_INDEX = 109

// Multicast TTL (Time To Live)
export const MULTICAST_TTL = 32

//------------------------------------------------------------------------------
// Protocol Limits
//------------------------------------------------------------------------------

export const MAX_DMX_SLOTS = 512 // Maximum DMX slots per universe
export const MIN_UNIVERSE = 1 // Minimum valid universe number
export const MAX_UNIVERSE = 63999 // Maximum valid universe number
export const MAX_UDP_PAYLOAD = 1400 // Maximum single UDP packet size (bytes)
export const COAP_HEADER_SIZE = 4 // CoAP header is always 4 bytes
export const UNIVERSE_DECIMAL_BUFFER_SIZE = 8 // "63999" + null
export const URI_STRING_MIN_BUFFER = 96 // URI path buffer with scoped paths

//------------------------------------------------------------------------------
// Transmission Timing (Section 10.6.2)
//------------------------------------------------------------------------------

export const MAX_ACTIVE_RATE_HZ = 44 // Maximum transmission rate when data changing
export const KEEPALIVE_RATE_HZ = 1 // Keep-alive rate when idle
export const STREAM_LOSS_TIMEOUT_MS = 3000 // Stream loss timeout (milliseconds)

//------------------------------------------------------------------------------
// Cryptographic Constants
//------------------------------------------------------------------------------

export const K0_KEY_LENGTH = 32 // 256-bit root key (bytes)
export const DERIVED_KEY_LENGTH = 32 // All derived keys are 256-bit (bytes)
export const HMAC_SHA256_LENGTH = 32 // HMAC-SHA256 digest length (bytes)
export const TUID_LENGTH = 6 // TUID is 6 bytes (48-bit)
export const TUID_HEX_LENGTH = 12 // TUID hex chars (without null terminator)
export const ENDPOINT_LENGTH = 2 // Endpoint is 2 bytes (16-bit)
export const SENDER_ID_LENGTH = 8 // Sender-ID = TUID + Endpoint (bytes)
export const HKDF_INFO_INPUT_MAX = 63 // info bytes before HKDF counter byte
export const HKDF_COUNTER_T1 = 0x01 // HKDF counter for first block T(1)

//------------------------------------------------------------------------------
// Sig-Net URI Path Components
//------------------------------------------------------------------------------

export const SIGNET_URI_PREFIX = 'sig-net'
export const SIGNET_URI_VERSION = 'v1'
export const SIGNET_URI_SCOPE_DEFAULT = 'local'
export const SIGNET_URI_SCOPE_MAX_LENGTH = 32
export const SIGNET_URI_LEVEL = 'level' // For TID_LEVEL messages
export const SIGNET_URI_PRIORITY = 'priority' // For TID_PRIORITY messages
export const SIGNET_URI_SYNC = 'sync' // For TID_SYNC messages
export const SIGNET_URI_NODE = 'node' // For /node/{tuid}/{endpoint} messages
export const SIGNET_URI_NODE_LOST = 'node_lost' // For /node_lost/{tuid} Lost-Mode messages
export const SIGNET_URI_POLL = 'poll' // For /poll discovery messages

// Fixed administrative multicast addresses (Appendix A)
export const MULTICAST_NODE_SEND_IP = '239.254.255.253' // /sig-net/<version>/<scope>/node/{tuid}/{endpoint}
export const MULTICAST_MANAGER_POLL_IP = '239.254.255.252' // /sig-net/<version>/<scope>/poll
export const MULTICAST_MANAGER_SEND_IP = '239.254.255.251' // manager/{tuid}/{endpoint} -- manager commands to node
export const MULTICAST_TIME_IP = '239.254.255.250' // sync + timecode/{stream} -- time distribution
export const MULTICAST_NODE_BEACON_IP = '239.254.255.255' // node_beacon/{tuid} -- unprovisioned node beacon
export const MULTICAST_NODE_LOST_IP = '239.254.255.254' // node_lost/{tuid} -- node leaving network

//------------------------------------------------------------------------------
// Key Derivation Info Strings (Section 7.3)
//------------------------------------------------------------------------------

export const HKDF_INFO_SENDER = 'Sig-Net-Sender-v1'
export const HKDF_INFO_CITIZEN = 'Sig-Net-Citizen-v1'
export const HKDF_INFO_MANAGER_GLOBAL = 'Sig-Net-Manager-v1'
export const HKDF_INFO_MANAGER_LOCAL_PREFIX = 'Sig-Net-Manager-v1-' // Append 12-char hex TUID

//------------------------------------------------------------------------------
// Error Codes
//------------------------------------------------------------------------------

export const SIGNET_SUCCESS = 0
export const SIGNET_ERROR_INVALID_ARG = -1 // Invalid argument
export const SIGNET_ERROR_BUFFER_FULL = -2 // Packet buffer overflow
export const SIGNET_ERROR_CRYPTO = -3 // Cryptographic operation failed
export const SIGNET_ERROR_ENCODE = -4 // Encoding error
export const SIGNET_ERROR_NETWORK = -5 // Network transmission failed
export const SIGNET_ERROR_BUFFER_TOO_SMALL = -6 // Insufficient data in buffer (parser)
export const SIGNET_ERROR_INVALID_PACKET = -7 // Malformed packet structure
export const SIGNET_ERROR_INVALID_OPTION = -8 // Missing or invalid CoAP option
export const SIGNET_ERROR_HMAC_FAILED = -9 // HMAC verification failed
export const SIGNET_TEST_FAILURE = -99 // Self-test failed

//------------------------------------------------------------------------------
// Passphrase Validation Return Codes (Section 7.2.3)
// Used for real-time validation of K0 passphrase entry
//------------------------------------------------------------------------------

export const SIGNET_PASSPHRASE_VALID = 0 // Passphrase meets all requirements
export const SIGNET_PASSPHRASE_TOO_SHORT = -10 // Length < 10 characters
export const SIGNET_PASSPHRASE_TOO_LONG = -11 // Length > 64 characters
export const SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES = -12 // < 3 character classes used
export const SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL = -13 // > 2 consecutive identical chars
export const SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL = -14 // > 3 consecutive sequential chars

//------------------------------------------------------------------------------
// Passphrase to K0 Derivation Parameters (Section 7.2.3)
// PBKDF2-HMAC-SHA256 configuration for converting passphrases to K0
//------------------------------------------------------------------------------

export const PBKDF2_SALT = 'Sig-Net-K0-Salt-v1' // Fixed 18-byte salt for PBKDF2
export const PBKDF2_ITERATIONS = 100000 // PBKDF2 iteration count
export const PASSPHRASE_MIN_LENGTH = 10 // Minimum passphrase length
export const PASSPHRASE_MAX_LENGTH = 64 // Maximum passphrase length
export const PASSPHRASE_GENERATED_LENGTH = 10 // Generated passphrase length

// Passphrase character sets (shared between validation and generator)
// prettier-ignore
export const PASSPHRASE_SYMBOLS = '!@#$%^&*()-_=+[]{}|;:\',.<>?/' // Allowed symbols for validation
export const PASSPHRASE_GEN_UPPERCASE = 'ABCDEFGHJKLMNPQRSTUVWXYZ' // Removed I, O for clarity
export const PASSPHRASE_GEN_LOWERCASE = 'abcdefghjkmnpqrstuvwxyz' // Removed i, l, o for clarity
export const PASSPHRASE_GEN_DIGITS = '23456789' // Removed 0, 1 for clarity
export const PASSPHRASE_GEN_SYMBOLS = '!@#$%^&*-_=+'

//------------------------------------------------------------------------------
// Test K0 for Development/Testing
// K0: 32 bytes (64 hex chars)
//------------------------------------------------------------------------------
export const TEST_K0 = '52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173'
export const TEST_PASSPHRASE = 'Ge2p$E$4*A'

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
// Manufacturer identity - SINGLE SOURCE OF TRUTH.
// ESTA Manufacturer ID for Singularity (UK) Ltd: 'S' (0x53) 'y' (0x79) = 0x5379.
// Every SoemCode and TUID manufacturer prefix MUST derive from this constant -
// never hard-code the manufacturer ID anywhere else.
//------------------------------------------------------------------------------
export const SIGNET_MANUFACTURER_ID = 0x5379

// Test TUID for Development/Testing.
// Format: Manufacturer ID (2 bytes) + Device ID (4 bytes) = 0x5379 + 00000001.
// (Must match SIGNET_MANUFACTURER_ID above.)
export const TEST_TUID = '537900000001'

//------------------------------------------------------------------------------
// SoemCode Assignments = (SIGNET_MANUFACTURER_ID << 16) | Product Variant
//------------------------------------------------------------------------------
export const SoemCodeNetWorkshop = (SIGNET_MANUFACTURER_ID << 16) | 0x0001
export const SoemCodeSdkLevelTx = (SIGNET_MANUFACTURER_ID << 16) | 0x0010
export const SoemCodeSdkPoller = (SIGNET_MANUFACTURER_ID << 16) | 0x0011
export const SoemCodeSdkNode = (SIGNET_MANUFACTURER_ID << 16) | 0x0012

//------------------------------------------------------------------------------
// Role Capability Bit Positions (TID_RT_ROLE_CAPABILITY, Section 11.6.9)
//------------------------------------------------------------------------------

export const ROLE_CAP_NODE = 0x01 // Bit 0: Node role supported
export const ROLE_CAP_SENDER = 0x02 // Bit 1: Sender role supported
export const ROLE_CAP_MANAGER = 0x04 // Bit 2: Manager role supported

//------------------------------------------------------------------------------
// Device Status Bit Positions (TID_RT_STATUS, Section 11.6.8)
//------------------------------------------------------------------------------

export const RT_STATUS_HW_FAULT = 0x00000001 // Bit 0: Hardware fault
export const RT_STATUS_FACTORY_BOOT = 0x00000002 // Bit 1: Booted from factory defaults
export const RT_STATUS_CONFIG_LOCK = 0x00000004 // Bit 2: Configuration locked via local UI

//------------------------------------------------------------------------------
// Endpoint Capability Bit Positions (TID_EP_CAPABILITY, Section 11.7.4)
//------------------------------------------------------------------------------

export const EP_CAP_CONSUME_LEVEL = 0x01 // Bit 0: Can consume TID_LEVEL
export const EP_CAP_SUPPLY_LEVEL = 0x02 // Bit 1: Can supply TID_LEVEL
export const EP_CAP_CONSUME_RDM = 0x04 // Bit 2: Can consume RDM
export const EP_CAP_SUPPLY_RDM = 0x08 // Bit 3: Can supply RDM
export const EP_CAP_VIRTUAL = 0x10 // Bit 4: Virtual endpoint (internal RDM responder)

//------------------------------------------------------------------------------
// Endpoint Direction Bit Positions (TID_EP_DIRECTION, Section 11.7.5)
// Bits 0-1 are the EpDirection enum below; Bit 2 is RDM enable
//------------------------------------------------------------------------------

export const EP_DIR_RDM_ENABLE = 0x04 // Bit 2: RDM processing enabled on this endpoint

//------------------------------------------------------------------------------
// Endpoint Status Bit Positions (TID_EP_STATUS, Section 11.7.7)
//------------------------------------------------------------------------------

export const EP_STATUS_DATA_ACTIVE = 0x00000001 // Bit 0: Data activity on endpoint
export const EP_STATUS_HW_FAULT = 0x00000002 // Bit 1: Hardware fault
export const EP_STATUS_CONFIG_LOCK = 0x00000004 // Bit 2: Configuration locked via local UI

//------------------------------------------------------------------------------
// Magic Word Constants
//------------------------------------------------------------------------------

export const UNPROVISION_MAGIC_WORD = 0x57495045 // ASCII "WIPE" -- required payload for TID_RT_UNPROVISION
export const REBOOT_MAGIC_WORD = 0x424F4F54 // ASCII "BOOT" -- required prefix for TID_RT_REBOOT

//------------------------------------------------------------------------------
// TID Payload Enumerations
//------------------------------------------------------------------------------

// TID_TIMECODE type byte values (Section 11.2.4)

// TID_RDM_TOD_CONTROL command byte values (Section 11.3.3)

// TID_NW_IPV4_MODE mode byte values (Section 11.5.2)

// TID_NW_IPV6_MODE mode byte values (Section 11.5.7)

// TID_RT_MULT / TID_RT_MULT_OVERRIDE global routing state values (Section 11.6.6)

// TID_RT_IDENTIFY state byte values (Section 11.6.7)

// TID_RT_REBOOT command type byte values (Section 11.6.10)

// TID_EP_DIRECTION direction field (Bits 0-1) values (Section 11.7.5)

// TID_EP_FAILOVER mode byte values (Section 11.7.8)

// TID_EP_DMX_TIMING transmission mode byte values (Section 11.7.9)

// TID_EP_DMX_TIMING output timing byte values (Section 11.7.9)

// TID_DG_SECURITY_EVENT event code values (Section 11.8.1)

// TID_DG_SECURITY_EVENT source address type values (Section 11.8.1)
