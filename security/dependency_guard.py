"""Guard against dependency-confusion attacks.

The module enforces a small, deliberately strict policy:

* internal names (reserved prefixes / scopes) may only be fetched from a
  private registry;
* scoped names must use an allow-listed scope;
* lock-file entries must resolve to an approved (private) host over HTTPS;
* versions must be exact (no wildcards or ranges);
* only strong hashes (sha256/384/512) are accepted;
* VCS, URL and local-path requirements are rejected;
* names are normalised (PEP 503) before any policy decision so that
  ``Company_Utils`` and ``company-utils`` cannot bypass a check;
* transitive lock entries are validated recursively;
* empty or syntactically invalid names are rejected.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from urllib.parse import urlsplit

__all__ = [
    "parse_requirement",
    "registry_allowed",
    "is_internal_name",
    "validate_lock",
    "hash_ok",
    "normalize_name",
    "is_exact_version",
]

# --------------------------------------------------------------------------
# Policy configuration
# --------------------------------------------------------------------------

#: Reserved prefixes for first-party packages (compared after normalisation).
INTERNAL_PREFIXES = ("company-",)

#: Scopes that belong to the organisation.  Any other scope is not allowed.
INTERNAL_SCOPES = frozenset({"company"})

#: Exact first-party names (in addition to the prefixes above).
INTERNAL_NAMES = frozenset({"company"})

#: Hosts (and host suffixes) of the private registry.
PRIVATE_REGISTRY_HOSTS = frozenset(
    {
        "internal",
        "localhost",
        "127.0.0.1",
        "::1",
        "registry.internal",
        "pkg.internal",
    }
)
PRIVATE_REGISTRY_SUFFIXES = (".internal",)

#: Hash algorithms considered strong enough for dependency pinning.
ALLOWED_HASH_ALGORITHMS = frozenset({"sha256", "sha384", "sha512"})

#: Registry specs understood by :func:`registry_allowed`.
_PRIVATE_REGISTRY_NAMES = frozenset(
    {"internal", "private", "internal-registry", "private-registry"}
)
_PUBLIC_REGISTRY_NAMES = frozenset({"public", "pypi", "npmjs", "default"})

# --------------------------------------------------------------------------
# Name handling
# --------------------------------------------------------------------------

_SCOPE_RE = re.compile(
    r"^@([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)/"
    r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)$"
)
_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?$")


def _normalize_part(part: str) -> str:
    """PEP 503 normalisation for one name component."""
    return re.sub(r"[-_.]+", "-", part).lower()


def normalize_name(name):
    """Return the normalised package name, or ``None`` if it is invalid.

    Empty names, names starting with a path separator and malformed scoped
    names are rejected.  Normalisation lowercases the name and collapses
    runs of ``-``, ``_`` and ``.`` into a single ``-`` so that look-alike
    spellings cannot sidestep the policy.
    """
    if not isinstance(name, str):
        return None
    raw = name.strip()
    if not raw:
        return None
    if raw.startswith("@"):
        match = _SCOPE_RE.fullmatch(raw)
        if match is None:
            return None
        return "@%s/%s" % (
            _normalize_part(match.group(1)),
            _normalize_part(match.group(2)),
        )
    if _NAME_RE.fullmatch(raw) is None:
        return None
    return _normalize_part(raw)


def is_internal_name(name) -> bool:
    """Return ``True`` when *name* is a reserved first-party package name."""
    normalized = normalize_name(name)
    if normalized is None:
        return False
    if normalized.startswith("@"):
        scope, _, _ = normalized[1:].partition("/")
        return scope in INTERNAL_SCOPES
    if normalized in INTERNAL_NAMES:
        return True
    return any(normalized.startswith(prefix) for prefix in INTERNAL_PREFIXES)


def _scope_allowed(normalized: str) -> bool:
    """Enforce the scope allow-list for scoped package names."""
    if not normalized.startswith("@"):
        return True
    scope, _, _ = normalized[1:].partition("/")
    return scope in INTERNAL_SCOPES


def is_exact_version(version) -> bool:
    """Return ``True`` only for a single, fully pinned version."""
    if not isinstance(version, str):
        return False
    value = version.strip()
    if not value or value == "*":
        return False
    if any(char in value for char in "*^~<>=!,"):
        return False
    return _VERSION_RE.fullmatch(value) is not None


# --------------------------------------------------------------------------
# Requirement parsing
# --------------------------------------------------------------------------

_SPEC_RE = re.compile(r"^(===|==|>=|<=|~=|!=|>|<)\s*(.+)$")
_FORBIDDEN_SCHEMES = (
    "git+",
    "hg+",
    "svn+",
    "bzr+",
    "file:",
    "http:",
    "https:",
)
_FORBIDDEN_CHARS = set("\\;|&`$\n\r\t")


def parse_requirement(requirement):
    """Parse ``name[extras]specifier`` into ``(normalised_name, version)``.

    The parser is intentionally strict: VCS requirements, URLs, local paths,
    environment markers, shell metacharacters and empty names all yield
    ``(None, None)``.  A wildcard/range specifier is returned as-is (for
    example ``('pkg', '*')``); callers must additionally use
    :func:`is_exact_version` before trusting it.
    """
    if not isinstance(requirement, str):
        return (None, None)
    text = requirement.strip()
    if not text:
        return (None, None)
    lowered = text.lower()
    if lowered.startswith(_FORBIDDEN_SCHEMES):
        return (None, None)
    if "://" in text or ("@" in text and not text.startswith("@")):
        return (None, None)
    if text.startswith(("-", ".", "/", "~")):
        return (None, None)
    if any(char in _FORBIDDEN_CHARS for char in text):
        return (None, None)

    # Extras do not affect the package identity; strip them before parsing.
    if "[" in text:
        head, _, rest = text.partition("[")
        extras, sep, tail = rest.partition("]")
        if not sep or not extras.strip():
            return (None, None)
        text = head + tail

    if ";" in text:  # environment markers are not accepted
        return (None, None)
    match = re.match(r"^([^\s=<>!~]+)\s*(.*)$", text)
    if match is None:
        return (None, None)
    raw_name, specifier = match.group(1), match.group(2).strip()

    normalized = normalize_name(raw_name)
    if normalized is None:
        return (None, None)

    if not specifier:
        return (normalized, None)

    spec_match = _SPEC_RE.fullmatch(specifier)
    if spec_match is None:
        return (None, None)
    operator, version = spec_match.group(1), spec_match.group(2).strip()
    if not version or any(char.isspace() for char in version):
        return (None, None)
    if "," in version:  # multi-clause specifiers are not a single requirement
        return (None, None)
    if operator in ("==", "==="):
        return (normalized, version)
    # Keep the operator so callers can tell a range from a pin.
    return (normalized, operator + version)


# --------------------------------------------------------------------------
# Registry policy
# --------------------------------------------------------------------------


def _is_private_host(host: str) -> bool:
    if not isinstance(host, str):
        return False
    host = host.rstrip(".").lower()
    if not host:
        return False
    if host in PRIVATE_REGISTRY_HOSTS:
        return True
    return any(
        host.endswith(suffix) and host != suffix.lstrip(".")
        for suffix in PRIVATE_REGISTRY_SUFFIXES
    )


def _registry_kind(registry):
    """Classify a registry description as ``'private'`` or ``'public'``."""
    if not isinstance(registry, str):
        return None
    value = registry.strip().lower()
    if not value:
        return None
    if value in _PRIVATE_REGISTRY_NAMES:
        return "private"
    if value in _PUBLIC_REGISTRY_NAMES:
        return "public"
    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme not in ("https", "http"):
            return None
        host = parts.hostname
        if host is None:
            return None
        return "private" if _is_private_host(host) else "public"
    if _is_private_host(value):
        return "private"
    return None


def registry_allowed(package, registry) -> bool:
    """Return whether *package* may be fetched from *registry*.

    Internal packages (reserved prefix or allow-listed scope) are only
    allowed from a private registry.  Unknown registry descriptions and
    scopes outside the allow-list are rejected outright.
    """
    normalized = normalize_name(package)
    if normalized is None:
        return False
    if not _scope_allowed(normalized):
        return False
    kind = _registry_kind(registry)
    if kind is None:
        return False
    if is_internal_name(normalized):
        return kind == "private"
    return True


# --------------------------------------------------------------------------
# Lock-file validation
# --------------------------------------------------------------------------


def _approved_resolved(url) -> bool:
    """Return ``True`` when a lock ``resolved`` URL points at the private registry."""
    if not isinstance(url, str):
        return False
    if not url or url != url.strip():
        return False
    parts = urlsplit(url)
    if parts.scheme != "https":
        return False
    if parts.username is not None or parts.password is not None:
        return False
    host = parts.hostname
    if not host:
        return False
    return _is_private_host(host)


def validate_lock(entry, _seen=None) -> bool:
    """Validate one lock-file entry, including transitive dependencies.

    An entry is valid when it has a well-formed name, resolves over HTTPS to
    an approved private host, uses an exact version when one is recorded, and
    carries only strong hashes.  Nested ``dependencies`` are validated
    recursively; string dependencies are rejected because they carry no
    provenance.  Cycles and duplicate normalised names are treated as invalid.
    """
    if not isinstance(entry, Mapping):
        return False
    if _seen is None:
        _seen = set()
    identity = id(entry)
    if identity in _seen:
        return False
    _seen.add(identity)

    name = entry.get("name")
    normalized = normalize_name(name)
    if normalized is None:
        return False
    if not _scope_allowed(normalized):
        return False
    if not _approved_resolved(entry.get("resolved")):
        return False

    if "registry" in entry and not registry_allowed(normalized, entry.get("registry")):
        return False

    if "version" in entry and not is_exact_version(entry.get("version")):
        return False

    for key in ("hash", "integrity"):
        if key in entry and _parse_digest(entry.get(key)) is None:
            return False

    dependencies = entry.get("dependencies")
    if dependencies is not None:
        if not isinstance(dependencies, (list, tuple)):
            return False
        seen_names = set()
        for dependency in dependencies:
            if not isinstance(dependency, Mapping):
                # A bare string has no source information we can verify.
                return False
            dependency_name = normalize_name(dependency.get("name"))
            if dependency_name is None or dependency_name in seen_names:
                return False
            seen_names.add(dependency_name)
            if not validate_lock(dependency, _seen):
                return False

    return True


# --------------------------------------------------------------------------
# Hash verification
# --------------------------------------------------------------------------


def _parse_digest(value):
    """Split ``algo:hexdigest``; return ``None`` for missing/weak digests."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    algorithm, separator, digest = text.partition(":")
    if not separator:
        return None
    algorithm = algorithm.strip().lower()
    digest = digest.strip().lower()
    if algorithm not in ALLOWED_HASH_ALGORITHMS:
        return None
    if not digest or re.fullmatch(r"[0-9a-f]+", digest) is None:
        return None
    return algorithm, digest


def hash_ok(expected, actual) -> bool:
    """Return ``True`` when both hashes are strong, same-algorithm and equal."""
    expected_digest = _parse_digest(expected)
    actual_digest = _parse_digest(actual)
    if expected_digest is None or actual_digest is None:
        return False
    if expected_digest[0] != actual_digest[0]:
        return False
    return hmac.compare_digest(expected_digest[1], actual_digest[1])
