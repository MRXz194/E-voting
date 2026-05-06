"""
  1. Bỏ phiếu nhiều lần với cùng token (Double-voting)
  2. Tái sử dụng credential với token giả (Credential Reuse)
  3. Đăng ký nhiều lần để lấy nhiều credential (Registration Abuse)
  4. Bỏ phiếu bằng credential giả mạo (Forged Credential)
  5. Luồng hoàn chỉnh hợp lệ (Happy Path E2E)
  6. Xác thực HMAC chống tampering
  7. Mã bí mật sai (Secret Code Mismatch)
  8. Bỏ phiếu ngoài giai đoạn hợp lệ
"""
import pytest
import json
from app import app, db, Voter, Ballot, ElectionConfig
from crypto.blind_sig import (
    RSAPublicKey, rsa_keygen, blind_token,
    sign_blinded, unblind_signature, verify_credential
)
from crypto.hmac_utils import compute_packet_hmac



@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.test_client() as c:
        with app.app_context():
            db.drop_all()
            db.create_all()
        yield c



def _setup_election_and_get_credential(client, voter_id="voter1", token="secure_token_abc"):
    """
    Setup bầu cử, thêm voter, mở voting, đăng ký blind signature,
    và trả về (credential, token, c1, c2, hmac) sẵn sàng để bỏ phiếu.
    """
    # 1. Khởi tạo bầu cử
    client.post("/setup", data={"election_name": "Test Election", "candidates_str": "Alice, Bob"})

    # 2. Thêm voter và lấy secret_code
    client.post("/admin/add-voter", data={"voter_id": voter_id, "name": "Test Voter"})
    with app.app_context():
        voter = Voter.query.filter_by(voter_id=voter_id).first()
        secret_code = voter.secret_code

    # 3. Lấy public key của RA
    keys_res = client.get("/api/public-keys")
    keys = keys_res.get_json()
    rsa_n = int(keys["rsa"]["N"])
    rsa_e = int(keys["rsa"]["e"])
    pub = RSAPublicKey(rsa_n, rsa_e)

    # 4. Mở bỏ phiếu
    client.post("/admin/open-voting")

    # 5. Voter thực hiện Blind Signature
    blinded, r = blind_token(token, pub)
    reg_res = client.post("/api/register/sync", json={
        "voter_id": voter_id,
        "secret_code": secret_code,
        "blinded_token": str(blinded)
    })
    assert reg_res.status_code == 200, f"Registration failed: {reg_res.get_json()}"
    blind_sig = int(reg_res.get_json()["blind_signature"])

    # 6. Gỡ mù để lấy credential thật
    credential = unblind_signature(blind_sig, r, pub)

    # 7. Chuẩn bị vote payload hợp lệ (2 ứng viên)
    c1 = '["100", "200"]'
    c2 = '["300", "400"]'
    hmac_val = compute_packet_hmac(token, credential, c1, c2)

    return credential, token, c1, c2, hmac_val



def test_full_happy_path_flow(client):
    """Đăng ký → Bỏ phiếu hợp lệ → Nhận receipt thành công"""
    credential, token, c1, c2, hmac_val = _setup_election_and_get_credential(client)

    # Verify credential trực tiếp bằng thư viện crypto
    keys_res = client.get("/api/public-keys")
    keys = keys_res.get_json()
    pub = RSAPublicKey(int(keys["rsa"]["N"]), int(keys["rsa"]["e"]))
    assert verify_credential(token, credential, pub) is True

    # Bỏ phiếu
    vote_res = client.post("/api/vote", json={
        "voter_id_for_ui": "voter1",
        "token": token,
        "credential": str(credential),
        "c1_array": c1,
        "c2_array": c2,
        "packet_hmac": hmac_val
    })
    data = vote_res.get_json()
    assert vote_res.status_code == 200, f"Vote failed: {data}"
    assert "receipt" in data
    assert len(data["receipt"]) == 64  # SHA-256 hex digest



def test_double_voting_same_token_is_blocked(client):
    """
    QUAN TRỌNG: Cùng 1 token hợp lệ bỏ phiếu lần 2 PHẢI bị chặn.
    Server phải trả về 409 Conflict.
    """
    credential, token, c1, c2, hmac_val = _setup_election_and_get_credential(client)
    vote_payload = {
        "voter_id_for_ui": "voter1",
        "token": token,
        "credential": str(credential),
        "c1_array": c1,
        "c2_array": c2,
        "packet_hmac": hmac_val
    }

    # Lần 1: Phải thành công
    res1 = client.post("/api/vote", json=vote_payload)
    assert res1.status_code == 200, f"Lần đầu vote phải thành công: {res1.get_json()}"

    # Lần 2: Phải bị chặn với 409
    res2 = client.post("/api/vote", json=vote_payload)
    assert res2.status_code == 409, \
        f"Vote trùng PHẢI trả 409, nhưng nhận được {res2.status_code}: {res2.get_json()}"
    assert "đã được dùng" in res2.get_json()["error"]


def test_double_voting_1000_attempts_all_blocked(client):
    """
    Mô phỏng attacker cố gắng bỏ 1000 phiếu với 1 token → tất cả từ lần 2 trở đi phải bị block.
    """
    credential, token, c1, c2, hmac_val = _setup_election_and_get_credential(client)
    vote_payload = {
        "voter_id_for_ui": "voter1",
        "token": token,
        "credential": str(credential),
        "c1_array": c1,
        "c2_array": c2,
        "packet_hmac": hmac_val
    }

    success_count = 0
    rejected_count = 0

    for i in range(10):  # Mô phỏng 10 lần (đại diện cho 1000 lần)
        res = client.post("/api/vote", json=vote_payload)
        if res.status_code == 200:
            success_count += 1
        elif res.status_code == 409:
            rejected_count += 1

    assert success_count == 1, f"Chỉ được phép thành công 1 lần, nhưng thành công {success_count} lần!"
    assert rejected_count == 9, f"9 lần còn lại phải bị block, nhưng chỉ block {rejected_count} lần"

    # Xác nhận chỉ có 1 ballot trong DB
    with app.app_context():
        ballot_count = Ballot.query.count()
    assert ballot_count == 1, f"DB phải chứa đúng 1 phiếu, nhưng có {ballot_count} phiếu!"



def test_credential_cannot_be_reused_with_different_token(client):
    """
    Attacker lấy được credential hợp lệ và cố dùng nó với một token giả khác.
    Server phải từ chối vì signature không match token mới.
    """
    credential, token, c1, c2, _ = _setup_election_and_get_credential(client)

    # Tạo token giả — credential không match token này
    fake_token = "this_is_a_completely_different_token_xyz"
    fake_hmac = compute_packet_hmac(fake_token, credential, c1, c2)

    res = client.post("/api/vote", json={
        "voter_id_for_ui": "voter1",
        "token": fake_token,
        "credential": str(credential),
        "c1_array": c1,
        "c2_array": c2,
        "packet_hmac": fake_hmac
    })
    # Server phải từ chối vì verify_credential(fake_token, credential, pub) == False
    assert res.status_code == 403, \
        f"Credential không match token phải bị từ chối (403), nhận được {res.status_code}"
    assert "không hợp lệ" in res.get_json()["error"]



def test_double_registration_is_blocked(client):
    """
    Voter đã được cấp credential không thể đăng ký lần 2 để lấy credential mới.
    """
    credential, token, _, _, _ = _setup_election_and_get_credential(client)

    # Lấy lại public key để blind token thứ 2
    keys_res = client.get("/api/public-keys")
    keys = keys_res.get_json()
    pub = RSAPublicKey(int(keys["rsa"]["N"]), int(keys["rsa"]["e"]))

    with app.app_context():
        voter = Voter.query.filter_by(voter_id="voter1").first()
        secret_code = voter.secret_code

    # Cố đăng ký lần 2
    token2 = "a_second_token_attempt"
    blinded2, _ = blind_token(token2, pub)
    res = client.post("/api/register/sync", json={
        "voter_id": "voter1",
        "secret_code": secret_code,
        "blinded_token": str(blinded2)
    })
    assert res.status_code == 400, \
        f"Đăng ký lần 2 phải bị block (400), nhận được {res.status_code}"
    assert "Credential đã được cấp" in res.get_json()["error"]


# TEST 5: FORGED CREDENTIAL — Bỏ phiếu bằng credential tự tạo (không có RA ký)
def test_forged_credential_is_rejected(client):
    """
    Attacker tự tạo một số nguyên ngẫu nhiên làm credential mà không có RSA signature từ RA.
    Server phải từ chối vì verify_credential thất bại.
    """
    client.post("/setup", data={"election_name": "Test", "candidates_str": "A, B"})
    client.post("/admin/add-voter", data={"voter_id": "voter1", "name": "V1"})
    client.post("/admin/open-voting")

    forged_credential = 99999999999999  # Số ngẫu nhiên không hợp lệ
    token = "random_token"
    c1 = '["1", "1"]'
    c2 = '["2", "2"]'
    hmac_val = compute_packet_hmac(token, forged_credential, c1, c2)

    res = client.post("/api/vote", json={
        "token": token,
        "credential": str(forged_credential),
        "c1_array": c1,
        "c2_array": c2,
        "packet_hmac": hmac_val
    })
    assert res.status_code == 403, \
        f"Credential giả mạo phải bị từ chối (403), nhận được {res.status_code}"


# TEST 6: HMAC TAMPERING — Sửa đổi ciphertext sau khi ký HMAC
def test_tampered_ciphertexts_rejected_by_hmac(client):
    """
    Attacker có credential hợp lệ nhưng thay đổi c1/c2 (đổi lựa chọn bỏ phiếu).
    HMAC phải phát hiện sự thay đổi và từ chối.
    """
    credential, token, c1, c2, hmac_val = _setup_election_and_get_credential(client)

    # Sửa c1 nhưng giữ nguyên HMAC gốc (đã signed cho c1/c2 cũ)
    tampered_c1 = '["999", "888"]'  # Giá trị bị thay đổi

    res = client.post("/api/vote", json={
        "voter_id_for_ui": "voter1",
        "token": token,
        "credential": str(credential),
        "c1_array": tampered_c1,   # c1 đã bị tampering
        "c2_array": c2,
        "packet_hmac": hmac_val    # HMAC của dữ liệu gốc — sẽ không match nữa
    })
    assert res.status_code == 400, \
        f"HMAC mismatch phải bị từ chối (400), nhận được {res.status_code}"
    assert "HMAC" in res.get_json()["error"]


# TEST 7: WRONG SECRET CODE — Mã bí mật sai không được cấp credential
def test_wrong_secret_code_blocks_registration(client):
    """Voter nhập sai mã bí mật → RA từ chối ký mù."""
    client.post("/setup", data={"election_name": "Test", "candidates_str": "A, B"})
    client.post("/admin/add-voter", data={"voter_id": "voter1", "name": "V1"})
    client.post("/admin/open-voting")

    keys_res = client.get("/api/public-keys")
    keys = keys_res.get_json()
    pub = RSAPublicKey(int(keys["rsa"]["N"]), int(keys["rsa"]["e"]))

    blinded, _ = blind_token("some_token", pub)
    res = client.post("/api/register/sync", json={
        "voter_id": "voter1",
        "secret_code": "000000",  # Sai mã
        "blinded_token": str(blinded)
    })
    assert res.status_code == 403, \
        f"Sai mã bí mật phải trả 403, nhận {res.status_code}"


# TEST 8: VOTING OUTSIDE PHASE — Bỏ phiếu khi bầu cử chưa mở / đã đóng
def test_vote_before_election_opens(client):
    """Bỏ phiếu khi election status = 'setup' → phải từ chối."""
    client.post("/setup", data={"election_name": "Test", "candidates_str": "A, B"})
    # KHÔNG gọi /admin/open-voting

    res = client.post("/api/vote", json={
        "token": "t", "credential": "c",
        "c1_array": '["1"]', "c2_array": '["1"]',
        "packet_hmac": "fake"
    })
    assert res.status_code == 400
    assert "Chưa mở bỏ phiếu" in res.get_json()["error"]


def test_vote_after_election_closes(client):
    """Bỏ phiếu khi election status = 'tallying' → phải từ chối."""
    client.post("/setup", data={"election_name": "Test", "candidates_str": "A, B"})
    client.post("/admin/open-voting")
    client.post("/admin/close-voting")  # Chuyển sang giai đoạn tallying

    res = client.post("/api/vote", json={
        "token": "t", "credential": "c",
        "c1_array": '["1"]', "c2_array": '["1"]',
        "packet_hmac": "fake"
    })
    assert res.status_code == 400
    assert "Chưa mở bỏ phiếu" in res.get_json()["error"]


# TEST 9: UNAUTHORIZED VOTER — Người không có trong danh sách đăng ký
def test_unregistered_voter_cannot_get_credential(client):
    """Voter ID không tồn tại trong DB → RA từ chối ký mù."""
    client.post("/setup", data={"election_name": "Test", "candidates_str": "A, B"})
    client.post("/admin/open-voting")

    keys_res = client.get("/api/public-keys")
    keys = keys_res.get_json()
    pub = RSAPublicKey(int(keys["rsa"]["N"]), int(keys["rsa"]["e"]))
    blinded, _ = blind_token("hacker_token", pub)

    res = client.post("/api/register/sync", json={
        "voter_id": "hacker_not_in_list",
        "secret_code": "123456",
        "blinded_token": str(blinded)
    })
    assert res.status_code == 404


# TEST 10: BALLOT COUNT INTEGRITY — Tổng số phiếu trong DB phải chính xác
def test_ballot_count_matches_successful_votes(client):
    """
    Sau khi 3 voter hợp lệ bỏ phiếu, DB phải chứa đúng 3 ballot.
    Kiểm tra tính toàn vẹn của hòm phiếu.
    """
    client.post("/setup", data={"election_name": "Test", "candidates_str": "A, B"})
    client.post("/admin/open-voting")

    keys_res = client.get("/api/public-keys")
    keys = keys_res.get_json()
    pub = RSAPublicKey(int(keys["rsa"]["N"]), int(keys["rsa"]["e"]))

    for i in range(1, 4):
        voter_id = f"voter{i}"
        token = f"unique_token_for_voter_{i}"

        # Thêm voter
        client.post("/admin/add-voter", data={"voter_id": voter_id, "name": f"Voter {i}"})
        with app.app_context():
            v = Voter.query.filter_by(voter_id=voter_id).first()
            sc = v.secret_code

        # Đăng ký
        blinded, r = blind_token(token, pub)
        reg_res = client.post("/api/register/sync", json={
            "voter_id": voter_id,
            "secret_code": sc,
            "blinded_token": str(blinded)
        })
        assert reg_res.status_code == 200
        credential = unblind_signature(int(reg_res.get_json()["blind_signature"]), r, pub)

        # Bỏ phiếu
        c1 = '["10", "20"]'
        c2 = '["30", "40"]'
        hmac_val = compute_packet_hmac(token, credential, c1, c2)
        vote_res = client.post("/api/vote", json={
            "voter_id_for_ui": voter_id,
            "token": token,
            "credential": str(credential),
            "c1_array": c1,
            "c2_array": c2,
            "packet_hmac": hmac_val
        })
        assert vote_res.status_code == 200, f"Voter {i} vote failed: {vote_res.get_json()}"

    # Kiểm tra DB
    with app.app_context():
        count = Ballot.query.count()
    assert count == 3, f"Phải có đúng 3 phiếu trong DB, nhưng có {count}"
