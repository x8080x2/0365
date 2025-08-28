#!/bin/bash
cd /home/runner/workspace
uv run gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app