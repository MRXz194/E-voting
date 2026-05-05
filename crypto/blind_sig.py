"""
Dùng cho: Registration Authority cấp credential ẩn danh.

Nguyên lý: RA ký lên token mà KHÔNG thấy nội dung thật.
→ Voter có chữ ký hợp lệ nhưng RA không biết token là gì.
→ Tách biệt "ai đã đăng ký" khỏi "ai đã bầu".

Protocol:
  1. Voter chọn token t ngẫu nhiên
  2. Voter blind:  t̃ = r^e · H(t) mod N   (r = blinding factor bí mật)
  3. Voter → RA: gửi t̃ (RA không biết t)
  4. RA ký:       s̃ = t̃^d mod N
  5. RA → Voter: trả về s̃
  6. Voter unblind: s = s̃ · r⁻¹ mod N = H(t)^d mod N
  7. Xác minh:    s^e mod N = H(t) mod N ✓
"""
import random
from dataclasses import dataclass
from crypto.utils import mod_pow, mod_inverse, generate_prime, sha256_int, extended_gcd


@dataclass
class RSAPublicKey:
    N: int   # modulus N = p * q
    e: int   # public exponent

    def to_dict(self):
        return {"N": self.N, "e": self.e}


@dataclass
class RSAPrivateKey:
    N: int
    d: int   # d = e⁻¹ mod φ(N)
    e: int


def rsa_keygen(bits: int = 512):
    """Sinh cặp khóa RSA cho blind signature"""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    N = p * q
    phi_N = (p - 1) * (q - 1)
    e = 65537
    # Đảm bảo gcd(e, φ(N)) = 1
    while extended_gcd(e, phi_N)[0] != 1:
        e = random.randrange(3, phi_N, 2)
    d = mod_inverse(e, phi_N)
    return RSAPublicKey(N, e), RSAPrivateKey(N, d, e)


def blind_token(token: str, pub: RSAPublicKey) -> tuple[int, int]:
    """
    Bước 2: Voter blind token trước khi gửi RA.
    Trả về (blinded, r) — r phải giữ bí mật để unblind sau.
    """
    h = sha256_int(token) % pub.N
    # Chọn blinding factor r với gcd(r, N) = 1
    while True:
        r = random.randrange(2, pub.N)
        if extended_gcd(r, pub.N)[0] == 1:
            break
    blinded = (mod_pow(r, pub.e, pub.N) * h) % pub.N
    return blinded, r


def sign_blinded(blinded: int, priv: RSAPrivateKey) -> int:
    """
    Bước 4: RA ký lên blinded token.
    RA không cần biết token thật — chỉ ký mù.
    s̃ = blinded^d mod N
    """
    return mod_pow(blinded, priv.d, priv.N)


def unblind_signature(blind_sig: int, r: int, pub: RSAPublicKey) -> int:
    """
    Bước 6: Voter gỡ blinding factor để có chữ ký thật.
    s = s̃ · r⁻¹ mod N
    """
    r_inv = mod_inverse(r, pub.N)
    return (blind_sig * r_inv) % pub.N


def verify_credential(token: str, signature: int, pub: RSAPublicKey) -> bool:
    """
    Xác minh credential: kiểm tra s^e mod N = H(token) mod N.
    Bất kỳ ai cũng có thể verify (dùng public key của RA).
    """
    h = sha256_int(token) % pub.N
    recovered = mod_pow(signature, pub.e, pub.N)
    return recovered == h
