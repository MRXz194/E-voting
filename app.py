import json
import os
import hashlib
import random
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from sqlalchemy.pool import NullPool

from models import db, ElectionConfig, Voter, Ballot
from tasks import make_celery, register_tasks
from crypto.utils import sha256_hex
from crypto.elgamal import (
    ElGamalPublicKey, ElGamalPrivateKey, Ciphertext,
    elgamal_keygen, elgamal_encrypt, elgamal_decrypt,
    homomorphic_tally, recover_tally
)
from crypto.blind_sig import (
    RSAPublicKey, RSAPrivateKey,
    rsa_keygen, blind_token, sign_blinded, unblind_signature, verify_credential
)
from crypto.hmac_utils import compute_packet_hmac, verify_packet_hmac

#App config 
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-production-key-change-me")
is_production = os.environ.get("FLASK_ENV") == "production"
app.config["SESSION_COOKIE_SECURE"] = is_production
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///evoting.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["CELERY_BROKER_URL"] = "redis://localhost:6379/0"
app.config["CELERY_RESULT_BACKEND"] = "redis://localhost:6379/0"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"poolclass": NullPool}

db.init_app(app)
celery = make_celery(app)
sign_task = register_tasks(celery)

@app.template_filter("from_json")
def from_json_filter(s):
    if not s: return []
    return json.loads(s)

with app.app_context():
    db.create_all()


# HELPERS
def get_config():
    return ElectionConfig.query.first()

def load_eg_pub(cfg: ElectionConfig):
    return ElGamalPublicKey(int(cfg.eg_p), int(cfg.eg_g), int(cfg.eg_y))

def load_eg_priv(cfg: ElectionConfig):
    return ElGamalPrivateKey(int(cfg.eg_p), int(cfg.eg_g), int(cfg.eg_x))

def load_rsa_pub(cfg: ElectionConfig):
    return RSAPublicKey(int(cfg.rsa_N), int(cfg.rsa_e))

def load_rsa_priv(cfg: ElectionConfig):
    return RSAPrivateKey(int(cfg.rsa_N), int(cfg.rsa_d), int(cfg.rsa_e))


# DECORATORS
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app.config.get("TESTING") and session.get("role") != "admin":
            flash("Administrator access required.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def voter_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app.config.get("TESTING") and session.get("role") != "voter":
            flash("Voter access required. Please login.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ROUTES — TRANG CHỦ & AUTH
@app.route("/")
def index():
    cfg = get_config()
    voters_count = Voter.query.count()
    ballots_count = Ballot.query.count()
    return render_template("index.html", cfg=cfg, 
                           voters_count=voters_count, 
                           ballots_count=ballots_count)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form.get("role")
        if role == "admin":
            username = request.form.get("username")
            password = request.form.get("password")
            if username == "admin" and password == "admin":
                session["role"] = "admin"
                flash("Welcome back, Administrator.", "success")
                return redirect(url_for("admin"))
            else:
                flash("Invalid admin credentials.", "error")
        elif role == "voter":
            voter_id = request.form.get("voter_id")
            secret_code = request.form.get("secret_code")
            voter = Voter.query.filter_by(voter_id=voter_id, secret_code=secret_code).first()
            if voter:
                session["role"] = "voter"
                session["voter_id"] = voter.voter_id
                session["voter_name"] = voter.name
                flash(f"Welcome, {voter.name}.", "success")
                return redirect(url_for("voter_dashboard"))
            else:
                flash("Invalid Voter ID or Secret Code.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# ADMIN DASHBOARD
@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    cfg = get_config()
    
    if request.method == "POST":
        # Setup logic is now part of admin dashboard
        election_name = request.form.get("election_name")
        candidates_str = request.form.get("candidates_str", "")
        
        if not candidates_str:
            flash("Danh sách ứng viên không được để trống", "error")
            return redirect(url_for("admin"))
            
        candidates = [c.strip() for c in candidates_str.split(",") if c.strip()]
        if not candidates:
            flash("Vui lòng nhập ít nhất 1 ứng viên", "error")
            return redirect(url_for("admin"))
        
        eg_pub, eg_priv = elgamal_keygen(bits=256)
        rsa_pub, rsa_priv = rsa_keygen(bits=512)
        
        cfg = ElectionConfig(
            election_name=election_name,
            candidates=json.dumps(candidates),
            status="setup",
            eg_p=str(eg_pub.p), eg_g=str(eg_pub.g), eg_y=str(eg_pub.y),
            eg_x=str(eg_priv.x),
            rsa_N=str(rsa_pub.N), rsa_e=str(rsa_pub.e),
            rsa_d=str(rsa_priv.d)
        )
        
        Voter.query.delete()
        Ballot.query.delete()
        ElectionConfig.query.delete()
        
        db.session.add(cfg)
        db.session.commit()
        flash("✓ Thiết lập thành công! Khóa EA/RA đã được khởi tạo.", "success")
        return redirect(url_for("admin"))

    voters = Voter.query.all()
    ballots = Ballot.query.order_by(Ballot.submitted_at.desc()).all()
    candidates = json.loads(cfg.candidates) if cfg else []
    
    # Pre-compute tally if status is tallying
    results = []
    total_count = len(ballots)
    winner_obj = None
    if cfg and cfg.status == "tallying":
        eg_pub = load_eg_pub(cfg)
        eg_priv = load_eg_priv(cfg)
        max_votes = -1
        for i in range(len(candidates)):
            cts = []
            for b in ballots:
                c1_arr = json.loads(b.c1)
                c2_arr = json.loads(b.c2)
                cts.append(Ciphertext(int(c1_arr[i]), int(c2_arr[i])))
            
            agg_ct = homomorphic_tally(cts, eg_pub.p)
            g_to_sum = elgamal_decrypt(agg_ct, eg_priv)
            total_votes = recover_tally(g_to_sum, eg_pub.g, eg_pub.p, max_voters=max(1000, total_count))
            
            votes = total_votes or 0
            pct = round((votes / total_count * 100), 1) if total_count > 0 else 0
            res_item = {"candidate": candidates[i], "votes": votes, "pct": pct}
            results.append(res_item)
            if votes > max_votes:
                max_votes = votes
                winner_obj = res_item

    return render_template("admin_dashboard.html", cfg=cfg, voters=voters,
                           ballots=ballots, candidates=candidates,
                           results=results, winner=winner_obj, total_count=total_count)

@app.route("/admin/add-voter", methods=["POST"])
@admin_required
def add_voter():
    cfg = get_config()
    if not cfg:
        flash("Chưa setup bầu cử!", "error")
        return redirect(url_for("admin"))
    
    voter_id = request.form.get("voter_id", "").strip()
    name = request.form.get("name", "").strip()
    secret_code = "".join([str(random.randint(0, 9)) for _ in range(6)])
    
    if not voter_id:
        flash("Voter ID không được trống", "error")
        return redirect(url_for("admin"))
    if Voter.query.filter_by(voter_id=voter_id).first():
        flash(f"Lỗi: ID '{voter_id}' đã tồn tại!", "error")
        return redirect(url_for("admin"))
        
    db.session.add(Voter(voter_id=voter_id, name=name, secret_code=secret_code))
    db.session.commit()
    flash(f"✓ Đã thêm cử tri: {name or voter_id} (Mã bí mật: {secret_code})", "success")
    return redirect(url_for("admin"))

@app.route("/admin/add-bulk-voters", methods=["POST"])
@admin_required
def add_bulk_voters():
    added = 0
    for i in range(10):
        vid = f"voter{i+1}"
        if not Voter.query.filter_by(voter_id=vid).first():
            code = "".join([str(random.randint(0, 9)) for _ in range(6)])
            db.session.add(Voter(voter_id=vid, name=f"Cử tri {i+1}", secret_code=code))
            added += 1
    db.session.commit()
    flash(f"✓ Đã cấp thêm {added} cử tri ngẫu nhiên.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/open-voting", methods=["POST"])
@admin_required
def open_voting():
    cfg = get_config()
    if cfg:
        cfg.status = "voting"
        db.session.commit()
        flash("✓ Giai đoạn bỏ phiếu đã MỞ", "success")
    return redirect(url_for("admin"))

@app.route("/admin/close-voting", methods=["POST"])
@admin_required
def close_voting():
    cfg = get_config()
    if cfg:
        cfg.status = "tallying"
        db.session.commit()
        flash("✓ Đã ĐÓNG bỏ phiếu. Hệ thống sẽ tự động kiểm phiếu.", "success")
    return redirect(url_for("admin"))


# VOTER DASHBOARD
@app.route("/voter_dashboard")
@voter_required
def voter_dashboard():
    cfg = get_config()
    if not cfg:
        flash("Election has not been setup yet.", "error")
        return redirect(url_for("index"))
    
    voter = Voter.query.filter_by(voter_id=session["voter_id"]).first()
    candidates = json.loads(cfg.candidates) if cfg else []
    
    return render_template("voter_dashboard.html", cfg=cfg, voter=voter, candidates=candidates)


# PUBLIC APIs (Used by Frontend Crypto JS)
@app.route("/api/public-keys", methods=["GET"])
def get_public_keys():
    cfg = get_config()
    if not cfg: return jsonify({"error": "Chưa setup"}), 400
    rsa_pub = load_rsa_pub(cfg)
    eg_pub = load_eg_pub(cfg)
    return jsonify({
        "rsa": {"N": str(rsa_pub.N), "e": str(rsa_pub.e)},
        "elgamal": {"p": str(eg_pub.p), "g": str(eg_pub.g), "y": str(eg_pub.y)}
    })

@app.route("/api/register/sync", methods=["POST"])
def register_sync():
    """API cấp Credential ẩn danh (RSA Blind Sign)"""
    cfg = get_config()
    if not cfg: return jsonify({"error": "Chưa setup"}), 400

    data = request.get_json()
    voter_id = data.get("voter_id", "").strip()
    secret_code = data.get("secret_code", "").strip()
    blinded_int = int(data.get("blinded_token"))

    voter = Voter.query.filter_by(voter_id=voter_id).first()
    if not voter:
        return jsonify({"error": "Voter ID không tồn tại"}), 404
        
    if voter.secret_code and secret_code != voter.secret_code:
        return jsonify({"error": "Mã bí mật (Secret Code) sai!"}), 403
        
    if voter.status != "registered":
        return jsonify({"error": "Credential đã được cấp trước đó"}), 400

    rsa_priv = load_rsa_priv(cfg)
    blind_sig = sign_blinded(blinded_int, rsa_priv)

    voter.status = "credential_issued"
    db.session.commit()
    
    return jsonify({"blind_signature": str(blind_sig)})

@app.route("/api/vote", methods=["POST"])
def vote_api():
    cfg = get_config()
    if not cfg or cfg.status != "voting":
        return jsonify({"error": "Chưa mở bỏ phiếu"}), 400

    data = request.get_json()
    token = data.get("token")
    credential_str = data.get("credential")
    c1_json = data.get("c1_array")
    c2_json = data.get("c2_array")
    
    if not all([token, credential_str, c1_json, c2_json]):
        return jsonify({"error": "Dữ liệu phiếu bầu không đầy đủ"}), 400

    credential_int = int(credential_str)
    rsa_pub = load_rsa_pub(cfg)
    
    # 1. Verify HMAC (Chống sửa đổi Ciphertexts trên đường truyền)
    received_hmac = data.get("packet_hmac", "")
    if received_hmac:
        if not verify_packet_hmac(token, credential_int, c1_json, c2_json, received_hmac):
            return jsonify({"error": "Mã HMAC không khớp!", "step": "filtering_hmac"}), 400

    # 2. Verify RSA Credential (Bằng chứng được RA ký mù)
    if not verify_credential(token, credential_int, rsa_pub):
        return jsonify({"error": "Chữ ký Token không hợp lệ!", "step": "filtering_rsa"}), 403

    token_hash = sha256_hex(token)
    if Ballot.query.filter_by(token_hash=token_hash).first():
        return jsonify({"error": "Token này đã được dùng để bỏ phiếu!"}), 409

    receipt = sha256_hex(c1_json + c2_json + str(datetime.utcnow()))
    ballot = Ballot(token_hash=token_hash, c1=c1_json, c2=c2_json, receipt=receipt)
    db.session.add(ballot)

    voter = Voter.query.filter_by(voter_id=data.get("voter_id_for_ui", "")).first()
    if voter:
        voter.status = "voted"
        voter.voted_at = datetime.utcnow()

    db.session.commit()
    return jsonify({"receipt": receipt, "status": "success"})


# BULLETIN BOARD — Công khai & Xác minh
@app.route("/bulletin_board")
def bulletin_board():
    ballots = Ballot.query.order_by(Ballot.submitted_at.desc()).all()
    return render_template("bulletin_board.html", ballots=ballots)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
