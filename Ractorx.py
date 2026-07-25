import hashlib
import binascii

def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def parse_der_signature(sig_bytes: bytes):
    """
    Parses a standard ASN.1 DER encoded ECDSA signature to extract R and S.
    """
    try:
        if sig_bytes[0] != 0x30:
            return None
        length = sig_bytes[1]
        
        # Extract R
        if sig_bytes[2] != 0x02:
            return None
        r_len = sig_bytes[3]
        r_start = 4
        r_bytes = sig_bytes[r_start : r_start + r_len]
        
        # Extract S
        s_marker = r_start + r_len
        if sig_bytes[s_marker] != 0x02:
            return None
        s_len = sig_bytes[s_marker + 1]
        s_start = s_marker + 2
        s_bytes = sig_bytes[s_start : s_start + s_len]
        
        return int.from_bytes(r_bytes, 'big'), int.from_bytes(s_bytes, 'big')
    except Exception:
        return None

def extract_rsz_from_p2pkh_tx(tx_hex: str):
    """
    Extracts R, S, and calculates Z for legacy P2PKH transactions.
    Note: Highly complex transactions or SegWit require a dedicated parser.
    """
    try:
        tx_bytes = bytes.fromhex(tx_hex.strip())
        # Basic structural breakdown for simple 1-input legacy transactions
        # [Version: 4B][InCount: 1B][PrevOut: 36B][ScriptLen: 1B][ScriptSig][Sequence: 4B]...
        
        # Extracting the signature script component
        # For an accurate Z calculation, we simulate SIGHASH_ALL (01000000)
        # This requires stripping all scriptSigs except the one being evaluated,
        # which must be replaced with the original scriptPubKey it spends.
        
        # For security scanning environments, Z is frequently calculated or 
        # provided alongside the tx or extracted via blockchain APIs. 
        # Here is a template mapping to isolate DER components:
        
        # Locate DER signature boundary (0x30 ... 0x02)
        der_start = tx_bytes.find(b'\x30')
        if der_start == -1:
            return None
            
        # Extract plausible signature window (typically under 73 bytes)
        sig_len = tx_bytes[der_start + 1]
        der_sig = tx_bytes[der_start : der_start + sig_len + 2]
        
        # Pop the sighash byte (usually 0x01) from the end of the DER signature
        sighash_byte = der_sig[-1]
        clean_der = der_sig[:-1]
        
        rs = parse_der_signature(clean_der)
        if not rs:
            return None
        r, s = rs
        
        # Calculate Z (simplified example baseline for a single input)
        # To get the true Z, the full TX must be modified according to bip-143 or standard sighash flags.
        # This placeholder handles standard double-sha256 verification layouts.
        z_bytes = double_sha256(tx_bytes[:der_start] + b'\x00' + tx_bytes[der_start+sig_len+2:])
        z = int.from_bytes(z_bytes, 'big')
        
        return r, s, z
    except Exception as e:
        return None

def process_file(filename):
    results = []
    print(f"[*] Processing {filename}...")
    with open(filename, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            # Check if line is raw hex or already parsed
            if len(line) > 100 and all(c in '0123456789abcdefABCDEF' for c in line):
                extracted = extract_rsz_from_p2pkh_tx(line)
                if extracted:
                    results.append(extracted)
                else:
                    print(f"[-] Line {line_num}: Could not parse or compute Z from raw hex.")
            else:
                # Fallback if line is space-separated hex integers (R S Z)
                try:
                    parts = line.split()
                    if len(parts) >= 3:
                        results.append((int(parts[0], 16), int(parts[1], 16), int(parts[2], 16)))
                except ValueError:
                    pass
    return results
