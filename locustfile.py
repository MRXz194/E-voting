"""
stress test
Chạy:
  locust -f locustfile.py --host=http://localhost:5000

Hoặc headless (không cần UI):
  locust -f locustfile.py --host=http://localhost:5000 \
    -u 1000 -r 100 --run-time 60s --headless

Workflow mỗi voter:
  1. Đăng ký cử tri với server
  2. Blind token + gọi API /api/register/async → nhận task_id
  3. Poll kết quả → unblind → có credential
  4. Mã hóa phiếu ElGamal (local, không gọi server)
  5. Gọi API /api/vote với credential + ciphertext
"""
import json
import random
import time
import requests
from locust import HttpUser, task, between, events

# Lấy public keys 1 lần trước khi test
_public_keys = None

def get_public_keys(host):
    global _public_keys
    if _public_keys is None:
        r = requests.get(f"{host}/api/public-keys")
        _public_keys = r.json()
    return _public_keys


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Chạy trước khi stress test bắt đầu"""
    host = environment.host
    print(f"\n[Locust] Fetching public keys from {host}...")
    keys = get_public_keys(host)
    print(f"[Locust] ElGamal p = {str(keys['elgamal']['p'])[:30]}...")
    print(f"[Locust] RSA N    = {str(keys['rsa']['N'])[:30]}...")


class EVoterUser(HttpUser):
    """
    Mỗi Locust user = 1 cử tri chạy toàn bộ flow đăng ký → bỏ phiếu.
    wait_time: nghỉ 0.5–2 giây giữa các request (mô phỏng thực tế).
    """
    wait_time = between(0.5, 2)

    def on_start(self):
        """Khởi tạo khi user bắt đầu"""
        self.voter_id = f"stress_voter_{random.randint(10**8, 10**9)}"
        self.token = None
        self.credential = None
        self.eg_pub = None
        self.rsa_pub = None
        self._setup_crypto()

    def _setup_crypto(self):
        """Load public keys và chuẩn bị crypto objects"""
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        try:
            from crypto.blind_sig import RSAPublicKey, blind_token, unblind_signature
            from crypto.elgamal import ElGamalPublicKey, elgamal_encrypt

            keys = get_public_keys(self.client.base_url if hasattr(self, 'client') else "http://localhost:5000")
            eg = keys["elgamal"]
            rsa = keys["rsa"]
            self.eg_pub = ElGamalPublicKey(int(eg["p"]), int(eg["g"]), int(eg["y"]))
            self.rsa_pub = RSAPublicKey(int(rsa["N"]), int(rsa["e"]))
            self._blind_token = blind_token
            self._unblind = unblind_signature
            self._elgamal_encrypt = elgamal_encrypt
        except Exception as e:
            print(f"[Locust] Crypto setup error: {e}")

    @task
    def full_voting_flow(self):
        """Toàn bộ flow đăng ký + bỏ phiếu"""
        # Step 1: Tạo voter (admin tạo sẵn → dùng ID ngẫu nhiên hy vọng có)
        # Trong stress test thực tế: admin đã bulk-add voters trước

        if not self.rsa_pub or not self.eg_pub:
            return

        from crypto.utils import sha256_int

        # Step 2: Blind token
        self.token = f"tok_{self.voter_id}_{random.randint(10**9, 10**10)}"
        try:
            blinded, r = self._blind_token(self.token, self.rsa_pub)
        except Exception:
            return

        # Step 3: Request async sign
        with self.client.post("/api/register/async",
                              json={"voter_id": self.voter_id, "blinded_token": blinded},
                              catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"Register failed: {resp.status_code}")
                return
            task_id = resp.json().get("task_id")

        # Step 4: Poll result
        blind_sig = None
        for _ in range(20):  # max 20 polls
            time.sleep(0.1)
            r2 = self.client.get(f"/api/register/result/{task_id}")
            data = r2.json()
            if data.get("status") == "done":
                blind_sig = data.get("blind_signature")
                break

        if blind_sig is None:
            return

        # Step 5: Unblind → credential
        try:
            from crypto.blind_sig import unblind_signature
            credential = unblind_signature(int(blind_sig), r, self.rsa_pub)
        except Exception:
            return

        # Step 6: Encrypt vote zero-knowledge array (3 candidates max)
        candidate_idx = random.randint(0, 2)
        c1_arr = []
        c2_arr = []
        try:
            for i in range(3):
                v = 1 if i == candidate_idx else 0
                ct = self._elgamal_encrypt(v, self.eg_pub)
                c1_arr.append(str(ct.c1))
                c2_arr.append(str(ct.c2))
        except Exception:
            return

        import json
        c1_json = json.dumps(c1_arr)
        c2_json = json.dumps(c2_arr)

        # Compute HMAC
        try:
            import hashlib, hmac
            raw_key = f"{self.token}:{credential}"
            key = hashlib.sha256(raw_key.encode()).digest()
            payload = f"{self.token}|{c1_json}|{c2_json}".encode()
            hmac_val = hmac.new(key, payload, hashlib.sha256).hexdigest()
        except Exception:
            hmac_val = ""

        # Step 7: Submit vote
        with self.client.post("/api/vote",
                              json={
                                  "token": self.token,
                                  "credential": credential,
                                  "c1_array": c1_json,
                                  "c2_array": c2_json,
                                  "packet_hmac": hmac_val
                              },
                              catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            elif resp.status_code == 409:
                resp.failure("Double vote detected")
            else:
                resp.failure(f"Vote failed: {resp.status_code} {resp.text}")

        # Reset để có thể chạy lại (với voter_id mới)
        self.voter_id = f"stress_voter_{random.randint(10**8, 10**9)}"
