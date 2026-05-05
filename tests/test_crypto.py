import pytest
from crypto.utils import mod_pow, mod_inverse, sha256_int, baby_step_giant_step
from crypto.blind_sig import rsa_keygen, blind_token, sign_blinded, unblind_signature, verify_credential
from crypto.elgamal import elgamal_keygen, elgamal_encrypt, elgamal_decrypt, homomorphic_tally, recover_tally

def test_rsa_blind_signature_flow():
    """Test full cycle of Chaum's Blind Signature"""
    # 1. Setup RA
    pub, priv = rsa_keygen(bits=512)
    token = "unique_voter_token_123"
    
    # 2. Voter blinds token
    blinded, r = blind_token(token, pub)
    
    # 3. RA signs blinded token
    blind_sig = sign_blinded(blinded, priv)
    
    # 4. Voter unblinds to get real signature
    sig = unblind_signature(blind_sig, r, pub)
    
    # 5. Verification
    assert verify_credential(token, sig, pub) is True
    assert verify_credential("wrong_token", sig, pub) is False

def test_elgamal_homomorphic_property():
    """Test that multiplying ciphertexts equals sum of plaintexts"""
    pub, priv = elgamal_keygen(bits=256)
    
    # Vote 1: choice A (value 1)
    # Vote 2: choice A (value 1)
    # Vote 3: choice B (value 0)
    # Total A should be 2, Total B should be 0
    
    ct1 = elgamal_encrypt(1, pub)
    ct2 = elgamal_encrypt(1, pub)
    ct3 = elgamal_encrypt(0, pub)
    
    # Tally
    agg = homomorphic_tally([ct1, ct2, ct3], pub.p)
    
    # Decrypt
    g_to_sum = elgamal_decrypt(agg, priv)
    
    # Recover
    total = recover_tally(g_to_sum, pub.g, pub.p, max_voters=10)
    assert total == 2

def test_mod_inverse():
    assert mod_inverse(3, 11) == 4  # 3*4 = 12 = 1 mod 11
    with pytest.raises(ValueError):
        mod_inverse(2, 4) # gcd(2,4) != 1

def test_bsgs_discrete_log():
    p = 23
    g = 5
    x = 7
    target = pow(g, x, p) # 5^7 mod 23 = 78125 mod 23 = 17
    assert baby_step_giant_step(g, target, p, max_val=20) == 7
