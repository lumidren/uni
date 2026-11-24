"""Preloaded standards + organisational controls.

Each requirement carries:
  * ``control_tags`` — normalised topic tags (access_control, encryption, ...)
    used as *structural* evidence so a mapping is never claimed on text alone.
  * ``obligation_type`` — retain / delete / localize / transfer / protect /
    general. Contradictory obligation types are what let the engine flag a
    genuine cross-framework CONFLICT (e.g. retain-vs-delete, localize-vs-transfer)
    rather than a mere overlap.

Subsets are representative, not exhaustive — enough to demonstrate equivalence,
partial overlap, gaps and a real GDPR-vs-PDPL / retention-vs-erasure conflict.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Requirement:
    req_id: str
    framework: str
    title: str
    text: str
    control_tags: tuple[str, ...]
    obligation_type: str = "general"


@dataclass(frozen=True)
class Control:
    control_id: str
    name: str
    description: str
    satisfies_tags: tuple[str, ...]


# --------------------------------------------------------------------------- #
# Preloaded regulatory requirements
# --------------------------------------------------------------------------- #
REQUIREMENTS: list[Requirement] = [
    # ISO/IEC 27001 (Annex A excerpts)
    Requirement("ISO27001-A.9.2", "ISO_27001", "User access management",
                "The organization shall manage user access rights through a formal provisioning and de-provisioning process with least privilege.",
                ("access_control", "identity"), "protect"),
    Requirement("ISO27001-A.8.24", "ISO_27001", "Use of cryptography",
                "Information shall be protected by cryptographic controls including encryption of sensitive data at rest and in transit.",
                ("encryption", "data_protection"), "protect"),
    Requirement("ISO27001-A.8.15", "ISO_27001", "Logging",
                "Event logs recording user activities and security events shall be produced, kept and reviewed.",
                ("logging", "monitoring"), "retain"),
    Requirement("ISO27001-A.5.24", "ISO_27001", "Incident management",
                "The organization shall plan and prepare for managing information security incidents with defined responsibilities and procedures.",
                ("incident_response",), "general"),

    # PCI-DSS v4.0 (excerpts)
    Requirement("PCI-3.4", "PCI_DSS", "Protect stored account data",
                "Primary account numbers shall be rendered unreadable anywhere they are stored using strong cryptography.",
                ("encryption", "data_protection"), "protect"),
    Requirement("PCI-3.1", "PCI_DSS", "Retain account data minimally",
                "Keep cardholder data storage to a minimum and retain only as long as required for business, legal or regulatory purposes.",
                ("data_retention", "data_minimization"), "retain"),
    Requirement("PCI-8.3", "PCI_DSS", "Strong authentication",
                "Secure all access into the cardholder data environment with multi-factor authentication.",
                ("access_control", "authentication"), "protect"),
    Requirement("PCI-10.2", "PCI_DSS", "Audit logs",
                "Implement audit logs to reconstruct access to system components and cardholder data.",
                ("logging", "monitoring"), "retain"),

    # NIST SP 800-53 (excerpts)
    Requirement("NIST-AC-6", "NIST_800_53", "Least privilege",
                "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.",
                ("access_control", "identity"), "protect"),
    Requirement("NIST-SC-13", "NIST_800_53", "Cryptographic protection",
                "Implement cryptographic mechanisms to protect the confidentiality and integrity of information.",
                ("encryption", "data_protection"), "protect"),
    Requirement("NIST-AU-6", "NIST_800_53", "Audit review",
                "Review and analyze information system audit records for indications of inappropriate or unusual activity.",
                ("logging", "monitoring"), "retain"),
    Requirement("NIST-IR-4", "NIST_800_53", "Incident handling",
                "Implement an incident handling capability for security incidents including preparation, detection, containment and recovery.",
                ("incident_response",), "general"),

    # GDPR (EU 2016/679) excerpts
    Requirement("GDPR-Art17", "GDPR", "Right to erasure",
                "The data subject shall have the right to obtain erasure of personal data without undue delay upon request.",
                ("data_subject_rights", "data_deletion"), "delete"),
    Requirement("GDPR-Art20", "GDPR", "Right to data portability",
                "The data subject has the right to receive their personal data and to transmit it to another controller.",
                ("data_subject_rights", "data_portability"), "transfer"),
    Requirement("GDPR-Art33", "GDPR", "Breach notification",
                "The controller shall notify the supervisory authority of a personal data breach within 72 hours of becoming aware.",
                ("breach_notification", "incident_response"), "general"),
    Requirement("GDPR-Art32", "GDPR", "Security of processing",
                "Implement appropriate technical measures including encryption to ensure a level of security appropriate to the risk.",
                ("encryption", "data_protection"), "protect"),

    # Egypt PDPL (Law No. 151 of 2020) excerpts
    Requirement("PDPL-Art2", "EGYPT_PDPL", "Consent and data subject rights",
                "Processing of personal data requires consent, and the data subject may request correction, erasure or withdrawal.",
                ("data_subject_rights", "consent"), "delete"),
    Requirement("PDPL-Art14", "EGYPT_PDPL", "Cross-border transfer restriction",
                "Personal data may not be transferred outside the Arab Republic of Egypt except with a licence and adequate protection.",
                ("data_residency", "cross_border"), "localize"),
    Requirement("PDPL-Art7", "EGYPT_PDPL", "Breach notification",
                "The controller shall notify the Centre of a personal data breach within 72 hours.",
                ("breach_notification", "incident_response"), "general"),
    Requirement("PDPL-Art4", "EGYPT_PDPL", "Security obligations",
                "Controllers shall take technical and organizational measures to protect personal data from loss or unauthorized access.",
                ("encryption", "data_protection"), "protect"),
]


# --------------------------------------------------------------------------- #
# Organisational controls the enterprise has implemented
# --------------------------------------------------------------------------- #
CONTROLS: list[Control] = [
    Control("ORG-IAM-01", "Central IAM with least privilege + MFA",
            "Okta-style SSO enforcing least privilege and MFA on all sensitive systems.",
            ("access_control", "identity", "authentication")),
    Control("ORG-CRYPTO-01", "Encryption everywhere",
            "AES-256 at rest and TLS 1.2+ in transit across all data stores.",
            ("encryption", "data_protection")),
    Control("ORG-LOG-01", "Central logging & SIEM",
            "All hosts and appliances ship logs to the SIEM with 1-year retention and review.",
            ("logging", "monitoring", "data_retention")),
    Control("ORG-IR-01", "Incident response plan + CSIRT",
            "Documented IR plan, on-call CSIRT, and breach-notification runbook.",
            ("incident_response", "breach_notification")),
    Control("ORG-DSR-01", "Data subject request workflow",
            "Portal to action access, correction and erasure requests within SLA.",
            ("data_subject_rights", "data_deletion", "consent")),
    # NOTE: no control currently covers data_residency / cross_border -> a gap.
]


def requirements_by_framework() -> dict[str, list[Requirement]]:
    out: dict[str, list[Requirement]] = {}
    for r in REQUIREMENTS:
        out.setdefault(r.framework, []).append(r)
    return out


def all_corpus() -> dict[str, str]:
    """req_id -> text, for the TF-IDF index."""
    return {r.req_id: f"{r.title}. {r.text}" for r in REQUIREMENTS}
