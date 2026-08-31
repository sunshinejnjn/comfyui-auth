"""ComfyUI password authentication custom node.

Importing this package installs an aiohttp middleware on ComfyUI's web app.
The package intentionally exposes no workflow nodes: authentication is a
server-level concern rather than something that belongs in a workflow.
"""

from .auth_middleware import install_auth_middleware

install_auth_middleware()

NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]
