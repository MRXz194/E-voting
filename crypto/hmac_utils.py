"""
HMAC-SHA256 Utility
Dùng để xác thực tính toàn vẹn và nguồn gốc của packet khi gửi qua BB (Bulletin Board).
"""
import hmac
import hashlib

def _derive_key(token: str, credential: int) -> bytes:
    """Derive key từ token + credential. Không bao giờ gửi qua mạng."""
    raw_key = f"{token}:{credential}"
    return hashlib.sha256(raw_key.encode()).digest()

def compute_packet_hmac(token: str, credential: int, c1_json: str, c2_json: str) -> str:
    """Tính HMAC-SHA256 cho payload (token|c1_json|c2_json)"""
    key = _derive_key(token, credential)
    payload = f"{token}|{c1_json}|{c2_json}".encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()

def verify_packet_hmac(token: str, credential: int, c1_json: str, c2_json: str, expected_hmac: str) -> bool:
    """Kiểm tra HMAC có khớp không"""
    actual_hmac = compute_packet_hmac(token, credential, c1_json, c2_json)
    return hmac.compare_digest(actual_hmac, expected_hmac)
