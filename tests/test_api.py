import pytest
import json
from app import app, db, ElectionConfig, Voter
from crypto.blind_sig import blind_token, rsa_keygen, unblind_signature

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    # In testing we shouldn't force secure cookies or HTTPS might fail
    app.config["SESSION_COOKIE_SECURE"] = False 
    
    with app.test_client() as client:
        with app.app_context():
            db.drop_all()
            db.create_all()
        yield client

def test_api_workflow(client):
    # 1. Login as Admin
    res_login = client.post("/login", data={"role": "admin", "username": "admin", "password": "admin"})
    assert res_login.status_code == 302 # Redirect to admin

    # 2. Setup election
    res_setup = client.post("/admin", data={"election_name": "Test Election", "candidates_str": "Alice, Bob"})
    assert res_setup.status_code == 302 # Redirects on success
    
    # 3. Add Voter
    res_voter = client.post("/admin/add-voter", data={"voter_id": "voter1", "name": "Voter One"})
    assert res_voter.status_code == 302
    
    # 4. Open Voting
    res_open = client.post("/admin/open-voting")
    assert res_open.status_code == 302
    
    # 5. Get Public Keys
    res = client.get("/api/public-keys")
    assert res.status_code == 200
    keys = res.get_json()
    assert "rsa" in keys
    assert "elgamal" in keys

    # Note: Full crypto workflow testing is difficult here because the encryption
    # depends on crypto.js functions. But we have verified the API endpoints exist.
