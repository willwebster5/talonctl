"""talonctl -- Infrastructure as code for CrowdStrike NGSIEM."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("talonctl")
except PackageNotFoundError:
    # Package is not installed (running from source without pip install -e)
    try:
        from talonctl._version import __version__  # type: ignore[no-redef]
    except ImportError:
        __version__ = "0.0.0.dev0"
