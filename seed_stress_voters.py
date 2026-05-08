from app import app, db, Voter

def seed_stress_voters():
    with app.app_context():
        print("Đang xóa các voter stress cũ (nếu có)...")
        Voter.query.filter(Voter.voter_id.like("stress_voter_%")).delete(synchronize_session=False)
        db.session.commit()

        print("Đang tạo 10.000 voters cho stress test...")
        voters = []
        for i in range(10000):
            voters.append(Voter(
                voter_id=f"stress_voter_{i}",
                name=f"Stress Voter {i}",
                secret_code=f"secret_{i}",
                status="registered"
            ))
            
            # Commit theo batch để tránh tràn RAM
            if len(voters) >= 1000:
                db.session.bulk_save_objects(voters)
                voters = []
                print(f"  Đã insert {i+1}/10000...")
                
        if voters:
            db.session.bulk_save_objects(voters)
            
        db.session.commit()
        print("Hoàn tất tạo 10.000 stress_voter_xxx!")

if __name__ == "__main__":
    seed_stress_voters()
