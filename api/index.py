"""Vercel entry point for the public Faultline demo.

This serves the same dashboard as ``faultline web`` in hosted mode: the page tells
visitors that uploads go to the demo server (and are deleted after analysis), and
uploads are limited to 4 MB, Vercel's request size limit. ``FAULTLINE_SECRET`` is
set in the Vercel project settings, never in the repository.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from faultline.web.app import create_app  # noqa: E402

app = create_app(max_upload_mb=4, hosted=True)
