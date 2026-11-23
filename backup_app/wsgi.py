"""WSGI entry point: ``python -m backup_app.wsgi`` or gunicorn-style import."""

import logging

from .web import create_app

app = create_app()

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # threaded=True lets uploads/downloads proceed while rotation ticks run.
    app.run(host="0.0.0.0", port=8000, threaded=True)
