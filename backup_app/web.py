"""Flask application: single-page backup console plus JSON API."""

import logging
import os

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    send_file,
    url_for,
)
from io import BytesIO

from .config import config_from_env
from .db import check_crypto_import
from .service import KeyRemovalError, RotationInProgress, Service
from .worker import RotationWorker

log = logging.getLogger(__name__)


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def create_app(config=None) -> Flask:
    config = config or config_from_env()
    check_crypto_import()

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
    # The UI only uses flash messages; an ephemeral secret is fine and avoids
    # persisting one next to the master keys.
    app.secret_key = os.urandom(32)
    app.jinja_env.filters["human_size"] = human_size

    service = Service(config)
    app.extensions["backup_service"] = service

    worker = RotationWorker(service, config.rotation_interval)
    worker.start()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/")
    def index():
        return render_template("index.html", **service.dashboard())

    @app.post("/backups")
    def upload():
        from flask import request

        upload = request.files.get("file")
        if upload is None or upload.filename == "":
            flash("请选择要上传的文件。", "error")
            return redirect(url_for("index"))
        data = upload.read()
        try:
            backup_id = service.upload_backup(upload.filename, data)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))
        flash(f"备份已创建：{backup_id[:8]}…（独立数据密钥加密）", "ok")
        return redirect(url_for("index"))

    @app.get("/backups/<backup_id>/download")
    def download(backup_id: str):
        result = service.download_backup(backup_id)
        if result is None:
            abort(404)
        filename, plaintext = result
        return send_file(
            BytesIO(plaintext),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=filename,
        )

    @app.post("/rotations")
    def start_rotation():
        try:
            job_id = service.start_rotation()
            flash(f"密钥轮换已启动（任务 {job_id[:8]}…），后台逐份重包装数据密钥。", "ok")
        except RotationInProgress as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/rotations/tick")
    def manual_tick():
        # Convenience endpoint for demos/tests; the worker already ticks.
        processed = service.rotation_tick()
        flash(f"本次轮换推进了 {processed} 份备份。", "ok")
        return redirect(url_for("index"))

    @app.post("/keys/<key_id>/remove")
    def remove_key(key_id: str):
        try:
            service.remove_key(key_id)
            flash(f"旧主密钥 {key_id[:8]}… 已移除，密钥文件已粉碎。", "ok")
        except KeyRemovalError as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.errorhandler(413)
    def too_large(_):
        flash(f"文件超过上限（{config.max_content_length // (1024 * 1024)} MB）。", "error")
        return redirect(url_for("index"))

    return app
