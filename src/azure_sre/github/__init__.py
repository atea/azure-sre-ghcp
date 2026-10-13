"""Application-owned GitHub issue publication over the official GitHub MCP server.

The model never connects to GitHub: the host renders a fixed template, launches the
pinned ``github-mcp-server`` per operation with native GitHub App authentication and
reports only verified outcomes (see ``docs/publication.md``).
"""

from azure_sre.github.mcp_client import (
    McpSetupError,
    PublisherSession,
    SessionFactory,
    ToolResponse,
    open_publisher_session,
    safe_child_environment,
    stdio_session_factory,
)
from azure_sre.github.publisher import McpPublisher, PrivateKeyLoaderFn
from azure_sre.github.render import (
    MAX_TITLE_CHARS,
    RenderError,
    escape_inline,
    marker_comment,
    render_issue_body,
    render_issue_title,
    render_recovery_comment,
    starts_with_marker,
)
from azure_sre.github.tool_schemas import (
    EXPECTED_TOOLS,
    SchemaMismatchError,
    check_advertised_tools,
)

__all__ = [
    "EXPECTED_TOOLS",
    "MAX_TITLE_CHARS",
    "McpPublisher",
    "McpSetupError",
    "PrivateKeyLoaderFn",
    "PublisherSession",
    "RenderError",
    "SchemaMismatchError",
    "SessionFactory",
    "ToolResponse",
    "check_advertised_tools",
    "escape_inline",
    "marker_comment",
    "open_publisher_session",
    "render_issue_body",
    "render_issue_title",
    "render_recovery_comment",
    "safe_child_environment",
    "starts_with_marker",
    "stdio_session_factory",
]
