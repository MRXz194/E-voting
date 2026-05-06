import pytest
from app import app, db
from crypto.hmac_utils import verify_packet_hmac

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.test_client() as client:
        with app.app_context():
            db.drop_all()
            db.create_all()
        yield client

def test_unauthorized_voter_registration(client):
    """RA should not sign token for voter not in list"""
    client.post("/admin", data={"election_name": "Test Election", "candidates_str": "A, B"})
    res = client.post("/api/register/sync", json={
        "voter_id": "intruder_123",
        "secret_code": "123456",
        "blinded_token": "12345"
    })
    assert res.status_code == 404  # Server returns 404 for missing voter

def test_tampered_hmac_packet(client):
    """Voting should fail if HMAC doesn't match payload"""
    client.post("/admin", data={"election_name": "Test Election", "candidates_str": "A, B"})
    client.post("/admin/open-voting") # MUST OPEN VOTING FIRST
    token = "token123"
    credential = "999" # fake
    c1 = '["1"]'
    c2 = '["2"]'
    wrong_hmac = "totally_wrong_hmac"
    
    res = client.post("/api/vote", json={
        "token": token,
        "credential": credential,
        "c1_array": c1,
        "c2_array": c2,
        "packet_hmac": wrong_hmac
    })
    assert res.status_code in [400, 403]

def test_voting_session_not_open(client):
    """Should fail if election status is not 'voting'"""
    # Just setup, but don't 'open-voting'
    client.post("/admin", data={"election_name": "Test Election", "candidates_str": "A, B"})
    res = client.post("/api/vote", json={"token": "t", "credential": "c"})
    assert res.status_code == 400
    assert "Chưa mở bỏ phiếu" in res.get_json()["error"]

def test_tallying_before_voting_closed(client):
    """Tallying page should redirect or warn if status is not 'tallying'"""
    client.post("/admin", data={"election_name": "Test Election", "candidates_str": "A, B"})
    # Status is 'setup' right now
    res = client.get("/admin", follow_redirects=True)
    # Check for the warning message in the response text (using substring)
    assert "Tallying is Locked" in res.get_data(as_text=True)
