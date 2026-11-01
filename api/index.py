"""Vercel entry point for the public Faultline demo.

This serves the same dashboard as ``faultline web`` in hosted mode: the page tells
visitors that uploads go to the demo server (and are deleted after analysis), and
uploads are limited to 4 MB (Vercel's request size limit) unless
``FAULTLINE_MAX_UPLOAD_MB`` says otherwise, as on a self-hosted server. ``FAULTLINE_SECRET`` is
set in the Vercel project settings, never in the repository.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from faultline.web.app import create_app  # noqa: E402

def _upload_limit_mb() -> int:
    try:
        return max(1, min(200, int(os.environ.get("FAULTLINE_MAX_UPLOAD_MB", "4"))))
    except ValueError:
        return 4


app = create_app(max_upload_mb=_upload_limit_mb(), hosted=True)
