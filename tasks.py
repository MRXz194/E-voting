"""
Celery Tasks — Xử lý RSA sign bất đồng bộ
RSA-512 sign mất ~1ms → 100K registrations cần offload sang worker pool.
Dùng Redis làm broker + result backend.
"""
from celery import Celery

def make_celery(app):
    celery = Celery(
        app.import_name,
        broker=app.config["CELERY_BROKER_URL"],
        backend=app.config["CELERY_RESULT_BACKEND"],
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


# Task được đăng ký sau khi app khởi tạo (xem app.py)
def register_tasks(celery):

    @celery.task(name="tasks.sign_blinded_token")
    def sign_blinded_token_task(blinded_int: int, rsa_d: int, rsa_N: int) -> int:
        """
        Worker thực hiện RSA sign:
          s̃ = blinded^d mod N
        Trả về blind signature dưới dạng int.
        """
        from crypto.utils import mod_pow
        return mod_pow(blinded_int, rsa_d, rsa_N)

    return sign_blinded_token_task
