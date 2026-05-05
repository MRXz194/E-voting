"""
Tất cả các phép tính nền tảng cho RSA và ElGamal.
"""
import random
import hashlib


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Lũy thừa mô-đun nhanh: base^exp mod mod (square-and-multiply)"""
    return pow(base, exp, mod)


def extended_gcd(a: int, b: int):
    """Giải thuật Euclid mở rộng — trả về (gcd, x, y) sao cho a*x + b*y = gcd"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def mod_inverse(a: int, m: int) -> int:
    """Nghịch đảo nhân: a^(-1) mod m. Yêu cầu gcd(a,m) = 1"""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Không tồn tại nghịch đảo: gcd({a},{m}) = {gcd}")
    return x % m


def is_prime(n: int, k: int = 20) -> bool:
    """Kiểm tra nguyên tố Miller-Rabin"""
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Sinh số nguyên tố ngẫu nhiên `bits` bit"""
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def generate_safe_prime(bits: int):
    """Sinh safe prime p = 2q+1 (p và q đều nguyên tố)"""
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if is_prime(p):
            return p, q


def find_generator(p: int) -> int:
    """Tìm generator g của nhóm Z_p* với safe prime p = 2q+1"""
    while True:
        h = random.randrange(2, p - 1)
        g = mod_pow(h, 2, p)
        if g != 1:
            return g


def sha256_hex(data: str) -> str:
    """Hash chuỗi thành hex SHA-256"""
    return hashlib.sha256(data.encode()).hexdigest()


def sha256_int(data: str) -> int:
    """Hash chuỗi thành số nguyên SHA-256"""
    return int(hashlib.sha256(data.encode()).hexdigest(), 16)


def baby_step_giant_step(g: int, target: int, p: int, max_val: int) -> int | None:
    """
    Baby-step Giant-step — tìm x sao cho g^x ≡ target (mod p)
    Dùng để giải discrete log nhỏ sau khi giải mã homomorphic.
    Độ phức tạp: O(√max_val) thay vì O(max_val)
    """
    import math
    m = math.isqrt(max_val) + 1
    # Baby steps: lưu bảng {g^j mod p : j}
    table = {}
    gj = 1
    for j in range(m + 1):
        table[gj] = j
        gj = (gj * g) % p
    # Giant steps: g^(m) factor
    gm_inv = mod_inverse(mod_pow(g, m, p), p)
    cur = target
    for i in range(m + 1):
        if cur in table:
            result = i * m + table[cur]
            if result <= max_val:
                return result
        cur = (cur * gm_inv) % p
    return None
