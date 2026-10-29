"""The single source of truth for Redfall's version.

Every other version string in the repository is checked against this by
`scripts/check_version.py`. Nothing else may declare a version independently:
drift between a wheel, a container tag and a Helm chart is how a customer ends up
running something nobody tested.
"""

__version__ = "0.3.0"
