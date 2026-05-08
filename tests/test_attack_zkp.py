import json
import hashlib
import hmac
import pytest
from app import app, db, Voter, get_config
from crypto.blind_sig import RSAPublicKey, blind_token, unblind_signature
from crypto.elgamal import ElGamalPublicKey, elgamal_encrypt

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.test_client() as client:
        with app.app_context():
            db.drop_all()
            db.create_all()
        yield client

def test_zkp_vulnerability_attack(client):
    """
    Kịch bản tấn công: Cử tri độc hại gửi 1000 phiếu cho Ứng viên A
    trong 1 lần bỏ phiếu duy nhất do hệ thống thiếu Zero-Knowledge Proof.
    """
    with app.app_context():
        # 1. EA Thiết lập cuộc bầu cử
        client.post("/admin", data={"election_name": "Test ZKP", "candidates_str": "Alice, Bob"})
        
        # 2. Thêm 1 cử tri
        client.post("/admin/add-voter", data={"voter_id": "hacker1", "name": "Hacker"})
        voter = Voter.query.filter_by(voter_id="hacker1").first()
        secret_code = voter.secret_code

        # 3. Mở hòm phiếu
        client.post("/admin/open-voting")

        # Lấy Public Keys từ API
        res = client.get("/api/public-keys")
        keys = res.get_json()
        
        eg_pub = ElGamalPublicKey(int(keys["elgamal"]["p"]), int(keys["elgamal"]["g"]), int(keys["elgamal"]["y"]))
        rsa_pub = RSAPublicKey(int(keys["rsa"]["N"]), int(keys["rsa"]["e"]))

        # 4. Hacker Đăng ký (Lấy chữ ký RSA ẩn danh)
        token = "hacker_token_123"
        blinded, r = blind_token(token, rsa_pub)
        
        res = client.post("/api/register/sync", json={
            "voter_id": "hacker1",
            "secret_code": secret_code,
            "blinded_token": str(blinded)
        })
        assert res.status_code == 200
        blind_sig = int(res.get_json()["blind_signature"])
        credential = unblind_signature(blind_sig, r, rsa_pub)

        # 5. MÃ HÓA PHIẾU ĐỘC HẠI (Vulnerability)
        # Hacker tự mã hóa số 1000 cho Alice thay vì số 1
        malicious_vote_alice = 1000  
        malicious_vote_bob = 0

        ct_alice = elgamal_encrypt(malicious_vote_alice, eg_pub)
        ct_bob = elgamal_encrypt(malicious_vote_bob, eg_pub)

        c1_array = json.dumps([str(ct_alice.c1), str(ct_bob.c1)])
        c2_array = json.dumps([str(ct_alice.c2), str(ct_bob.c2)])

        # Tính HMAC hợp lệ
        raw_key = f"{token}:{credential}"
        hmac_key = hashlib.sha256(raw_key.encode()).digest()
        payload = f"{token}|{c1_array}|{c2_array}".encode()
        packet_hmac = hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()

        # 6. Gửi phiếu
        res = client.post("/api/vote", json={
            "token": token,
            "credential": str(credential),
            "c1_array": c1_array,
            "c2_array": c2_array,
            "packet_hmac": packet_hmac
        })
        assert res.status_code == 200
        print(f"\n[+] Hacker gửi thành công phiếu mã hóa chứa {malicious_vote_alice} phiếu!")

        # 7. Đóng hòm phiếu và Kiểm phiếu
        client.post("/admin/close-voting")
        res = client.get("/admin")
        html_tally = res.get_data(as_text=True)

        # Kiểm tra xem hệ thống có thực sự cộng 1000 phiếu cho Alice không
        assert "1000" in html_tally
        print("\n[!] TẤN CÔNG THÀNH CÔNG: Alice nhận được 1000 phiếu chỉ từ 1 cử tri duy nhất!")
