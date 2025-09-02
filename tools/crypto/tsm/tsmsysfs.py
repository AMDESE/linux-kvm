#!/usr/bin/env python3
import sys
import struct
import argparse

# SPDM message codes
SPDM_GET_VERSION = 0x84
SPDM_VERSION = 0x04
SPDM_GET_CAPABILITIES = 0xE1
SPDM_CAPABILITIES = 0x61
SPDM_NEGOTIATE_ALGORITHMS = 0xE3
SPDM_ALGORITHMS = 0x63
SPDM_GET_MEASUREMENTS = 0xE0
SPDM_MEASUREMENTS = 0x60

# Measurement types
MEASUREMENT_TYPES = [
    "ImmuROM", "MutFW", "HWCfg", "FWCfg",
    "MeasMft", "DevDbg", "MutFWVer", "MutFWVerSec"
]

class SpdmMsgHdr:
    def __init__(self, data, offset=0):
        if len(data) - offset < 4:
            raise ValueError("Insufficient data for SPDM message header")
        self.ver, self.request_response_code, self.param1, self.param2 = \
            struct.unpack('<BBBB', data[offset:offset+4])

def skip_msgs(cmds, buf, offset=0):
    """Skip through SPDM messages based on expected command sequence"""
    pos = offset
    start_pos = pos

    for expected_cmd in cmds:
        if pos >= len(buf):
            break

        sh = SpdmMsgHdr(buf, pos)

        if expected_cmd != sh.request_response_code:
            print(f"Unexpected command at offset {pos}: {sh.request_response_code:02x}")

        # Skip based on message type
        if sh.request_response_code == SPDM_GET_VERSION:
            print("pos={:x} cmd={:x} SPDM_GET_VERSION".format(pos, sh.request_response_code))
            pos += 4
        elif sh.request_response_code == SPDM_VERSION:
            print("pos={:x} cmd={:x} SPDM_VERSION".format(pos, sh.request_response_code))
            pos += 6 + buf[pos + 5] * 2
        elif sh.request_response_code == SPDM_GET_CAPABILITIES:
            print("pos={:x} cmd={:x} SPDM_GET_CAPABILITIES".format(pos, sh.request_response_code))
            pos += 20
        elif sh.request_response_code == SPDM_CAPABILITIES:
            print("pos={:x} cmd={:x} SPDM_CAPABILITIES".format(pos, sh.request_response_code))
            pos += 20
        elif sh.request_response_code == SPDM_NEGOTIATE_ALGORITHMS:
            print("pos={:x} cmd={:x} SPDM_NEGOTIATE_ALGORITHMS".format(pos, sh.request_response_code))
            pos += buf[pos + 4]
        elif sh.request_response_code == SPDM_ALGORITHMS:
            print("pos={:x} cmd={:x} SPDM_ALGORITHMS".format(pos, sh.request_response_code))
            pos += buf[pos + 4]
        elif sh.request_response_code == SPDM_GET_MEASUREMENTS:
            print("pos={:x} cmd={:x} SPDM_GET_MEASUREMENTS".format(pos, sh.request_response_code))
            if (sh.param1 & 1):
                 print(f"Req nonce={hex_dump(buf[pos + 4:pos + 36], 32, True)}")
                 pos += 37
            else:
                 pos += 5
        elif sh.request_response_code == SPDM_MEASUREMENTS:
            print("pos={:x} cmd={:x} SPDM_MEASUREMENTS".format(pos, sh.request_response_code))
            pos += 8  # Skip header only, don't skip message body
            print("Parsing meas starting 0x{:x}".format(pos))

    return min(len(buf), pos - start_pos)

def hex_dump(data, length, txt):
    """Create a hex dump of data"""
    if len(data) > length:
        data = data[:length]
    hd = ''.join(f'{b:02x}' for b in data)
    if not txt:
        return hd
    ht = ''.join('{:c}'.format(c if c in range(0x20, 0x80) else ord('.')) for c in data)
    return hd + " | " + ht

def parse_measurements(data, transcript=True):
    """Parse SPDM measurements from buffer"""
    vca = [SPDM_GET_VERSION, SPDM_VERSION, SPDM_GET_CAPABILITIES,
           SPDM_CAPABILITIES, SPDM_NEGOTIATE_ALGORITHMS, SPDM_ALGORITHMS]
    req_resp = [SPDM_GET_MEASUREMENTS, SPDM_MEASUREMENTS]

    off = 0
    if transcript:
        off += skip_msgs(vca, data, off)

    while off < len(data):
        if transcript:
            off += skip_msgs(req_resp, data, off)
            if off >= 8:
                meas_len = data[off - 8 + 5] + (data[off - 8 + 6] << 8) + (data[off - 8 + 7] << 16)
                print("NumberOfBlocks={:d}".format(data[off - 8 + 4]))
            else:
                meas_len = len(data)
        else:
            meas_len = len(data)

        print("Measurements block {:x}..{:x}".format(off, off + meas_len - 1))
        meas_end = off + meas_len
        while off < meas_end and off < len(data):
            if off + 4 > len(data):
                break

            # Parse measurement block header
            mb_index, mb_spec, mb_size = struct.unpack('<BBH', data[off:off+4])
            dmtf = mb_spec & 1

            print(f"#{mb_index} len={mb_size} ", end='')

            if dmtf:
                # DMTF measurement block
                if off + 4 + mb_size > len(data):
                    print("222")
                    break

                h_type, h_size = struct.unpack('<BH', data[off+4:off+7])
                what = h_type & 0x7F

                type_name = MEASUREMENT_TYPES[what] if what < len(MEASUREMENT_TYPES) else "reserved"
                digest_or_raw = "digest" if (h_type & 0x80) else "raw"

                print(f"{off:x}..{off+mb_size-1:x} {h_type:02x}=[{digest_or_raw} {type_name} {h_type:x} {h_size:x}]: ", end='')

                if what == 5:  # DevDbg
                    if off + 6 + 8 <= len(data):
                        dm_data = data[off+7:off+7+16]
                        opmode_cap, opmode_sta, devmode_cap, devmode_sta = \
                            struct.unpack('<LLLL', dm_data)
                        print(f"{opmode_cap:04x} {opmode_sta:04x} {devmode_cap:04x} {devmode_sta:04x}")
                    else:
                        print("(insufficient data)")
                else:
                    # Hex dump of measurement data
                    meas_data = data[off+7:off+7+mb_size]
                    print(f"{hex_dump(meas_data, 32, False)}", end='')
            else:
                # Non-DMTF measurement block
                print(f"spec={mb_spec:04x}: ", end='')
                meas_data = data[off+6:off+6+min(mb_size, len(data)-off-6)]
                print(f"{hex_dump(meas_data, 32, False)}", end='')

            off += 4 + mb_size
            print("...")

        print(f"Resp nonce={hex_dump(data[off:off + 32], 32, True)}")
        print("OpaqueDataLength={:x}".format(struct.unpack('<H', data[off+32:off+34])[0]))

        if transcript:
            off += meas_len + 34

def parse_certificates(data):
    """Parse and display SPDM certificate blocks from buffer (Python version of tsm_certs_gen)"""
    class SpdmCertchainBlockHeader:
        def __init__(self, data, offset=0):
            if len(data) - offset < 4:
                raise ValueError("Insufficient data for certchain block header")
            self.length, self.reserved = struct.unpack('<HH', data[offset:offset+4])

    n = 0
    off = 0
    i = 0
    while off < len(data):
        if len(data) - off < 4:
            break
        h = SpdmCertchainBlockHeader(data, off)
        if h.length > len(data) - off:
            print(f"Block {i}: length {h.length} exceeds remaining data {len(data) - off}")
            break
        print(f"[{i}] len={h.length}:")
        o2 = 0
        p = off + 4
        while o2 < h.length - 4:
            chunk_len = min(32, h.length - 4 - o2)
            chunk = data[p + o2:p + o2 + chunk_len]
            print(hex_dump(chunk, 32, True))
            o2 += chunk_len
        off += h.length
        i += 1

def parse_report(data):
    """Parse and display TSM report from buffer (Python version of tsm_report_gen)"""
    def field_get(mask, value):
        return (value & mask) != 0

    def get_bits(val, mask, shift=0):
        return (val & mask) >> shift

    if len(data) < 24:
        print("Data too short for TSM report header")
        return
    # struct tdi_report_header: 2+2+2+2+4+4 = 16 bytes
    h = struct.unpack('<HHHHLL', data[:16])
    interface_info = h[0]
    msi_x_message_control = h[2]
    lnr_control = h[3]
    tph_control = h[4]
    mmio_range_count = h[5]
    print(f"no_fw_update={1 if (interface_info & (1 << 0)) else 0}" +
        f", dma_no_pasid={1 if (interface_info & (1 << 1)) else 0}" +
        f", dma_pasid={1 if (interface_info & (1 << 2)) else 0}" +
        f", ats={1 if (interface_info & (1 << 3)) else 0}" +
        f", prs={1 if (interface_info & (1 << 4)) else 0}" +
        f", msi_x_message_control={msi_x_message_control:#04x}" +
        f", lnr_control={lnr_control:#04x}, tph_control={tph_control:#08x}")
    off = 16
    # struct tdi_report_mmio_range: 8+4+4 = 16 bytes each
    for i in range(mmio_range_count):
        if off + 16 > len(data):
            print(f"Not enough data for MMIO range {i}")
            break
        first_page, num, range_attributes = struct.unpack('<QLL', data[off:off+16])
        range_id = (range_attributes >> 16) & 0xFFFF
        msix = '+' if (range_attributes & (1 << 0)) else '-'
        pba = '+' if (range_attributes & (1 << 1)) else '-'
        nontee = '+' if (range_attributes & (1 << 2)) else '-'
        upd = '+' if (range_attributes & (1 << 3)) else '-'
        if num < (1<<(20-12)):
                numstr = "{:d}KB".format(num << 2)
        elif num < (1<<(30-12)):
                numstr = "{:d}MB".format(num >> (20-12))
        else:
                numstr = "{:d}GB".format(num >> (30-12))
        print(f"range#{i} BAR{range_id} 0x{first_page << 12:016x} +0x{num << 12:x} ({numstr}) MSIX{msix} PBA{pba} NonTEE{nontee} Upd{upd}")
        if (range_attributes & 0xFFF0):
            print(f"[{i}] WARN: reserved={range_attributes:#x}")
        off += 16
    # struct tdi_report_footer: 4 bytes + variable
    if off + 4 > len(data):
        return
    device_specific_info_len = struct.unpack('<I', data[off:off+4])[0]
    off += 4
    if device_specific_info_len:
        num = min(len(data) - off, device_specific_info_len)
        print(f"DevSp len={device_specific_info_len}{': ' if num else ''}", end='')
        if num:
            print(hex_dump(data[off:off+num], 32, False))
        print("\n" if num else "...\n")

def spdm_algos_to_str(algos):
    names = [
        "DHE_SECP256R1",
        "DHE_SECP384R1",
        "AEAD_AES_128_GCM",
        "AEAD_AES_256_GCM",
        "ASYM_TPM_ALG_RSASSA_3072",
        "ASYM_TPM_ALG_ECDSA_ECC_NIST_P256",
        "ASYM_TPM_ALG_ECDSA_ECC_NIST_P384",
        "HASH_TPM_ALG_SHA_256",
        "HASH_TPM_ALG_SHA_384",
        "KEY_SCHED_SPDM_KEY_SCHEDULE",
    ]
    out = []
    for i, name in enumerate(names):
        if algos & (1 << i):
            out.append(name)
    return ' '.join(out)

def tdisp_state_to_str(state):
    states = ["CONFIG_UNLOCKED", "CONFIG_LOCKED", "RUN", "ERROR"]
    if 0 <= state < len(states):
        return states[state]
    return "unknown"

def tdi_status_to_str(status):
    ss = ["bound", "invalid", "unbound"]
    if 0 <= status < len(ss):
        return ss[status]
    return "{:d}==unknown".format(status)

def parse_tdi_status(data):
    """Parse and display tsm_tdi_status struct from buffer, using tsm_tdi_status_user_show() logic"""
    if len(data) < 1+1+1+1+1+1+1+1+2+8+48*3+8+4+8:
        print("Data too short for tsm_tdi_status struct")
        return
    off = 0
    # Unpack the first 8 bytes (8 u8 fields)
    status, state, meas_digest_fresh, meas_digest_valid, all_request_redirect, bind_p2p, lock_msix, no_fw_update = struct.unpack_from('<8B', data, off)
    off += 8
    # Next: u16 cache_line_size, u16 reserved
    cache_line_size = struct.unpack_from('<H', data, off)
    off += 2
    # Next: u64 spdm_algos
    spdm_algos = struct.unpack_from('<Q', data, off)[0]
    off += 8
    # Next: 3x 48 bytes
    certs_digest = data[off:off+48]
    off += 48
    meas_digest = data[off:off+48]
    off += 48
    interface_report_digest = data[off:off+48]
    off += 48
    # Next: u64 intf_report_counter
    intf_report_counter = struct.unpack_from('<Q', data, off)[0]
    off += 8
    # Next: struct tdisp_interface_id (u32 + u8[8])
    function_id = struct.unpack_from('<I', data, off)[0]
    off += 4
    id_reserved = data[off:off+8]
    off += 8
    fw_tdi_id = struct.unpack_from('<Q', data, off)[0]
    off += 8
    print(f"status={tdi_status_to_str(status)} state={state}:{tdisp_state_to_str(state)}" +
        f" FW_TDI_ID={fw_tdi_id}" +
        f" report_counter={intf_report_counter}")
    print(f"meas_digest_fresh={meas_digest_fresh}" +
        f" meas_digest_valid={meas_digest_valid}" +
        f" all_request_redirect={all_request_redirect}" +
        f" bind_p2p={bind_p2p}" +
        f" lock_msix={lock_msix}" +
        f" no_fw_update={no_fw_update}")
    print(f"cache_line_size={cache_line_size}" +
        f" algos=0x{spdm_algos:x}:{spdm_algos_to_str(spdm_algos)}")
    print(f"Certs digest: {hex_dump(certs_digest, 48, False)}...")
    print(f"Measurements digest: {hex_dump(meas_digest, 48, False)}...")
    print(f"Interface report digest: {hex_dump(interface_report_digest, 48, False)}...")

def parse_dev_status(data):
    """Parse and display tsm_dev_status struct from buffer, using tsm_dev_status_show() logic"""
    # struct tsm_dev_status {
    #   u8 valid;
    #   u8 ctx_state;
    #   u8 tc_mask;
    #   u8 certs_slot;
    #   u8 no_fw_update;
    #   u8 reserved[3];
    #   u16 device_id;
    #   u16 segment_id;
    #   u16 ide_stream_id[8];
    # };
    if len(data) < 8 + 2 + 2 + 16:
        print("Data too short for tsm_dev_status struct")
        return
    off = 0
    valid, ctx_state, tc_mask, certs_slot, no_fw_update, r0, r1, r2 = struct.unpack_from('<8B', data, off)
    off += 8
    device_id, segment_id = struct.unpack_from('<HH', data, off)
    off += 4
    ide_stream_id = struct.unpack_from('<8H', data, off)
    off += 16
    # Print as in tsm_dev_status_show
    print(f"valid={valid:x}")
    print(f"ctx_state={ctx_state:x}")
    print(f"tc_mask={tc_mask:x}")
    print(f"certs_slot={certs_slot:x}")
    print(f"device_id={(device_id >> 8) & 0xff:x}:{(device_id >> 3) & 0x1f:x}.{device_id & 0x07:x}")
    print(f"segment_id={segment_id:x}")
    print(f"no_fw_update={no_fw_update:x}")
    # ide_stream_id is not printed in tsm_dev_status_show

def main():
    parser = argparse.ArgumentParser(description="SPDM Measurements/Certificates/Report/TDI/DEV Status Parser")
    parser.add_argument('-m', '--measurements', action='store_true', help='Parse and display measurements')
    parser.add_argument('-c', '--certificates', action='store_true', help='Parse and display certificates')
    parser.add_argument('-r', '--report', action='store_true', help='Parse and display TSM report')
    parser.add_argument('--tdi', action='store_true', help='Parse and display tsm_tdi_status struct (TDI status)')
    parser.add_argument('--dev', action='store_true', help='Parse and display tsm_dev_status struct (DEV status)')
    parser.add_argument('filename', nargs='?', help='Input file to parse')
    args = parser.parse_args()

    if (not args.measurements and not args.certificates and not args.report and not args.tdi and not args.dev) or not args.filename:
        parser.print_help()
        sys.exit(1)

    filename = args.filename
    try:
        if filename == "-":
            buffer = sys.stdin.buffer.read()
            print(f"Read {len(buffer)} bytes from stdin")
        else:
            with open(filename, 'rb') as f:
                buffer = f.read()
            print(f"Read {len(buffer)} bytes from {filename}")
        if args.measurements:
            parse_measurements(buffer)
        if args.certificates:
            parse_certificates(buffer)
        if args.report:
            parse_report(buffer)
        if args.tdi:
            parse_tdi_status(buffer)
        if args.dev:
            parse_dev_status(buffer)
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
