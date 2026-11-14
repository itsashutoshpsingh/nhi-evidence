"""Check registry. Each module exposes META and run(snapshot, config) -> list[Finding]."""

from . import (
    c01_ownerless,
    c02_unused,
    c03_long_lived,
    c04_credential_hygiene,
    c05_secret_not_cert,
    c06_high_priv_app_perms,
    c07_tenant_wide_consent,
    c08_privileged_role,
    c09_loose_federation,
    c10_unverified_third_party,
    c11_environment_reuse,
    c12_no_workload_ca,
    c13_credential_paths,
    c14_human_use,
)

CHECKS = [c01_ownerless, c02_unused, c03_long_lived, c04_credential_hygiene, c05_secret_not_cert,
          c06_high_priv_app_perms, c07_tenant_wide_consent, c08_privileged_role, c09_loose_federation,
          c10_unverified_third_party, c11_environment_reuse, c12_no_workload_ca, c13_credential_paths,
          c14_human_use]
BY_ID = {c.META["id"]: c for c in CHECKS}
# NHI2 Secret Leakage has no check: secrets are never returned by Graph after creation, so leakage has
# to be found where secrets end up (repositories, CI logs) with a secret scanner such as gitleaks.
NOT_COVERED = {"NHI2": "Secret leakage is outside Graph's view; use a secret scanner on code and CI logs."}
