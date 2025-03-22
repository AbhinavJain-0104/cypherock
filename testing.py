def hex_to_int(hex_str):
    return int(hex_str, 16)

def verify_mta_shares(a_hex, b_hex, c_hex, d_hex):
    # secp256k1 order (from trezor's ecdsa.h)
    n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
    n = int(n_hex, 16)

    a = hex_to_int(a_hex)
    b = hex_to_int(b_hex)
    c = hex_to_int(c_hex)
    d = hex_to_int(d_hex)

    lhs = (c + d) % n
    rhs = (a * b) % n

    print(f"c + d mod n  = {hex(lhs)}")
    print(f"a * b mod n  = {hex(rhs)}")
    
    if lhs == rhs:
        print("✅ Verified: c + d ≡ a * b mod n")
    else:
        print("❌ Invalid: shares do not satisfy the equation")

# Example usage:
verify_mta_shares(
    "0000000000000000000000000000000000000000000000000000000000000000",  # a
    "0000000000000000000000000000000000000000000000000000000000000002",  # b
    "25f09b1bc93ebf79010bcfbe1cca9c4ac5e5f6276749179f9a53d7a16ee2eb65",  # c
    "da0f64e436c14086fef43041e33563b3f4c8e6bf47ff889c257e86eb615355dc"   # d
)
