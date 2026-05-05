"""
Dùng cho: mã hóa phiếu bầu + tính chất homomorphic để kiểm phiếu.

Tính chất homomorphic:
  Enc(g^v1) ⊗ Enc(g^v2) = Enc(g^(v1+v2))
  → Nhân tất cả ciphertext → giải mã 1 lần → ra tổng phiếu
"""
import random
from dataclasses import dataclass
from crypto.utils import mod_pow, mod_inverse, generate_safe_prime, find_generator, baby_step_giant_step


@dataclass
class ElGamalPublicKey:
    p: int   # safe prime lớn
    g: int   # generator của Z_p*
    y: int   # y = g^x mod p (public key)

    def to_dict(self):
        return {"p": self.p, "g": self.g, "y": self.y}


@dataclass
class ElGamalPrivateKey:
    p: int
    g: int
    x: int   # secret: 1 < x < p-1


@dataclass
class Ciphertext:
    c1: int  # c1 = g^k mod p
    c2: int  # c2 = m * y^k mod p

    def to_dict(self):
        return {"c1": self.c1, "c2": self.c2}

    @classmethod
    def from_dict(cls, d):
        return cls(c1=int(d["c1"]), c2=int(d["c2"]))


def elgamal_keygen(bits: int = 256):
    """
    Sinh cặp khóa ElGamal.
    Bảo mật dựa trên bài toán Discrete Logarithm Problem (DLP):
    Cho p, g, y = g^x mod p → tìm x là bài toán khó.
    """
    p, q = generate_safe_prime(bits)
    g = find_generator(p)
    x = random.randrange(2, p - 2)
    y = mod_pow(g, x, p)
    return ElGamalPublicKey(p, g, y), ElGamalPrivateKey(p, g, x)


def elgamal_encrypt(vote: int, pub: ElGamalPublicKey) -> Ciphertext:
    """
    Mã hóa phiếu bầu dạng 'encode-then-encrypt':
      m = g^vote mod p  (encode: 0→1, 1→g)
      k  = random nonce
      c1 = g^k mod p
      c2 = m * y^k mod p
    """
    m = mod_pow(pub.g, vote, pub.p)   # encode vote
    k = random.randrange(2, pub.p - 2)
    c1 = mod_pow(pub.g, k, pub.p)
    c2 = (m * mod_pow(pub.y, k, pub.p)) % pub.p
    return Ciphertext(c1, c2)


def elgamal_decrypt(ct: Ciphertext, priv: ElGamalPrivateKey) -> int:
    """
    Giải mã ElGamal:
      s   = c1^x mod p
      s⁻¹ = s^(-1) mod p
      M   = c2 * s⁻¹ mod p  →  M = g^(tổng phiếu)
    """
    s = mod_pow(ct.c1, priv.x, priv.p)
    s_inv = mod_inverse(s, priv.p)
    return (ct.c2 * s_inv) % priv.p


def homomorphic_tally(ciphertexts: list[Ciphertext], p: int) -> Ciphertext:
    """
    Tổng hợp phiếu đồng cấu (homomorphic aggregation):
      C1 = ∏ c1_i mod p
      C2 = ∏ c2_i mod p
    Giải mã C → g^(Σ votes) → dùng BSGS tìm Σ votes.
    Không cần giải mã từng phiếu riêng lẻ!
    """
    agg_c1 = 1
    agg_c2 = 1
    for ct in ciphertexts:
        agg_c1 = (agg_c1 * ct.c1) % p
        agg_c2 = (agg_c2 * ct.c2) % p
    return Ciphertext(agg_c1, agg_c2)


def recover_tally(g_to_sum: int, g: int, p: int, max_voters: int) -> int | None:
    """Dùng BSGS để tìm tổng từ g^tổng"""
    return baby_step_giant_step(g, g_to_sum, p, max_voters)
