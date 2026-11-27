"""Single source of truth for sensitive-path patterns shared by POL-09 and POL-10."""

from __future__ import annotations

# Core regex matching sensitive credential/key path suffixes (excluding .env.example).
V1_4_SENSITIVE_PATH_CORE = (
    r"""(?:^|(?<=[/\s"'<=`]))\.env(?![^/\s"'|;&]*\.example(?=[/\s"'|;&]|$))[^/\s"'|;&]*"""
    r"""|(?:^|(?<=[/\s"'<=`]))\.ssh/[^\s"'|;&]+"""
    r"""|(?:^|(?<=[/\s"'<=`]))\.netrc"""
    r"""|(?:^|(?<=[/\s"'<=`]))\.aws/credentials"""
    r"""|(?:^|(?<=[/\s"'<=`]))\.config/gcloud/[^\s"'|;&]+"""
    r"""|[^\s"'|;&]+\.pem"""
    r"""|(?:^|(?<=[/\s"'<=`]))id_[^\s"'|;&]+"""
)

SENSITIVE_PATH_CORE = (
    V1_4_SENSITIVE_PATH_CORE
    + r"""|(?:^|(?<=[\s"'<=`]))/etc/ssl/private(?:/[^\s"'|;&]*)?"""
    + r"""|[^\s"'|;&]+\.key(?=[/\s"'|;&)]|$)"""
    + r"""|(?:^|(?<=[/\s"'<=`]))private/[^\s"'|;&]+\.crt(?=[/\s"'|;&)]|$)"""
)
