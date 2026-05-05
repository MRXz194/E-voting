"""
Database layer — SQLite với SQLAlchemy
3 bảng chính theo thiết kế hệ thống:
  - election_config : cấu hình + public keys
  - voters          : danh sách cử tri + trạng thái
  - ballots         : phiếu bầu mã hóa (append-only)
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class ElectionConfig(db.Model):
    """Cấu hình cuộc bầu cử + ElGamal public key của EA"""
    __tablename__ = "election_config"
    id           = db.Column(db.Integer, primary_key=True)
    election_name = db.Column(db.String(200), nullable=False)
    candidates   = db.Column(db.Text, nullable=False)   # JSON list
    status       = db.Column(db.String(20), default="setup")
    # ElGamal public key (EA)
    eg_p         = db.Column(db.Text)
    eg_g         = db.Column(db.Text)
    eg_y         = db.Column(db.Text)
    # ElGamal private key (EA — chỉ lưu local demo)
    eg_x         = db.Column(db.Text)
    # RSA public key (RA)
    rsa_N        = db.Column(db.Text)
    rsa_e        = db.Column(db.Text)
    # RSA private key (RA — chỉ lưu local demo)
    rsa_d        = db.Column(db.Text)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)


class Voter(db.Model):
    """Danh sách cử tri đủ điều kiện"""
    __tablename__ = "voters"
    id           = db.Column(db.Integer, primary_key=True)
    voter_id     = db.Column(db.String(100), unique=True, nullable=False)
    name         = db.Column(db.String(200))
    secret_code  = db.Column(db.String(10), nullable=True) # Mã bí mật để đăng ký
    status       = db.Column(db.String(20), default="registered")
    # registered → credential_issued → voted
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    voted_at     = db.Column(db.DateTime)


class Ballot(db.Model):
    """
    Phiếu bầu mã hóa — Bulletin Board (append-only).
    Sau khi ghi vào không được sửa/xóa.
    Lưu ciphertext ElGamal dạng mảng JSON cho từng candidate.
    """
    __tablename__ = "ballots"
    id           = db.Column(db.Integer, primary_key=True)
    token_hash   = db.Column(db.String(64), unique=True, nullable=False)  # SHA-256 của token
    c1           = db.Column(db.Text, nullable=False)   # JSON Array ElGamal c1
    c2           = db.Column(db.Text, nullable=False)   # JSON Array ElGamal c2
    receipt      = db.Column(db.String(64), nullable=False)  # SHA-256(c1_json,c2_json,ts)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
