"""Single source of truth for the MT Pentester version.

Update the version in ONE place — here — or run:

    python bump_version.py X.Y.Z

The frontend (sidebar/About), the FastAPI backend (/, OpenAPI), and the README
badge all derive from this value, so they can never drift out of sync.
"""

__version__ = "3.0.0-alpha.3"
