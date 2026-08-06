"""
===============================================================================

Gen2X Security Engineering Platform

Module:
    evidence.py

Part I:
    Evidence Domain Models

===============================================================================

Business Objective
-------------------------------------------------------------------------------

Security providers observe the world.

Fusion reasons about those observations.

The classes in this module describe one observation without attempting to
interpret it.

By separating observations from analysis, Gen2X keeps evidence portable,
testable, and reusable across providers.

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from typing import Any

from models.enums import (
    IndicatorSource,
    IndicatorType,
    PlatformType,
    ProviderTrustLevel,
    ProviderType,
    ThreatCondition,
    ThreatConfidence,
    ThreatSeverity,
)


# =============================================================================
# Evidence Identity
# =============================================================================


@dataclass(slots=True)
class EvidenceIdentity:
    """
    Identifies one provider observation.

    Identity answers one question:

        "Who observed this, and when?"
    """

    evidence_id: str

    provider_name: str

    provider_type: ProviderType

    provider_platform: PlatformType

    provider_version: str = "1.0.0"

    observed_at: datetime = field(
        default_factory=datetime.utcnow
    )

    collected_at: datetime = field(
        default_factory=datetime.utcnow
    )

    @property
    def observation_key(self) -> str:
        """
        Return a deterministic identifier for this observation.

        Unlike evidence_id, the observation key identifies the
        observation itself rather than the record storing it.

        Useful for:

            • Duplicate detection

            • Correlation

            • Replay protection

            • Future distributed synchronization
        """

        source = "|".join(

            [

                self.provider_name.casefold(),

                self.provider_platform.value,

                self.provider_version,

                self.observed_at.isoformat(),

            ]

        )

        return sha256(
            source.encode("utf-8")
        ).hexdigest()


# =============================================================================
# Evidence Indicator
# =============================================================================


@dataclass(slots=True)
class EvidenceIndicator:
    """
    Represents what the provider observed.

    Indicators describe observations.

    They do not describe conclusions.
    """

    indicator_type: IndicatorType

    indicator_value: str

    indicator_source: IndicatorSource

    condition: ThreatCondition


# =============================================================================
# Evidence Source
# =============================================================================


@dataclass(slots=True)
class EvidenceSource:
    """
    Describes where the observation originated.

    These fields intentionally remain generic so they can
    represent AWS, Azure, GCP, GitHub, or on-premises systems.
    """

    account_id: str | None = None

    region: str | None = None

    resource_id: str | None = None

    repository: str | None = None

    hostname: str | None = None

    ip_address: str | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


# =============================================================================
# Evidence Context
# =============================================================================


@dataclass(slots=True)
class EvidenceContext:
    """
    Provides additional context for an observation.

    Context represents provider knowledge at the time the
    observation was collected.

    Fusion may later combine multiple observations into a
    different assessment.
    """

    severity: ThreatSeverity = ThreatSeverity.UNKNOWN

    confidence: ThreatConfidence = (
        ThreatConfidence.UNKNOWN
    )

    provider_trust: ProviderTrustLevel = (
        ProviderTrustLevel.UNKNOWN
    )

    expires_at: datetime | None = None

    tags: set[str] = field(
        default_factory=set
    )

    notes: str = ""


# =============================================================================
#
# Chewbacca's Commentary 🐾
#
# Before there is
#
# a threat...
#
# there is
#
# an observation.
#
# Before there is
#
# a conclusion...
#
# there is
#
# evidence.
#
# Good engineers
#
# resist
#
# the temptation
#
# to skip
#
# directly
#
# to answers.
#
# They first ask:
#
# "What do we actually know?"
#
# Everything else
#
# should be built
#
# on that foundation.
#
#                              — Chewbacca
#                                Chief Wookiee Architect
#
# =============================================================================



# =============================================================================
# Threat Evidence
# =============================================================================


@dataclass(slots=True)
class ThreatEvidence:
    """
    Represents one normalized security observation.

    ThreatEvidence is the common language spoken by every provider
    within the Gen2X platform.

    Providers observe.

    Fusion reasons.

    Reports communicate.

    ThreatEvidence intentionally represents observations rather than
    conclusions.
    """

    identity: EvidenceIdentity

    indicator: EvidenceIndicator

    source: EvidenceSource = field(
        default_factory=EvidenceSource
    )

    context: EvidenceContext = field(
        default_factory=EvidenceContext
    )

    # =========================================================================
    # Validation
    # =========================================================================

    def __post_init__(self) -> None:
        """
        Validate the ThreatEvidence model.
        """

        self.identity.provider_name = (
            self.identity.provider_name.strip()
        )

        self.indicator.indicator_value = (
            self.indicator.indicator_value.strip()
        )

        if not self.identity.provider_name:
            raise ValueError(
                "provider_name cannot be empty."
            )

        if not self.indicator.indicator_value:
            raise ValueError(
                "indicator_value cannot be empty."
            )

        if (
            self.context.expires_at is not None
            and
            self.context.expires_at
            <= self.identity.observed_at
        ):
            raise ValueError(
                "expires_at must occur after observed_at."
            )

    # =========================================================================
    # Forwarding Properties
    # =========================================================================

    @property
    def evidence_id(self) -> str:
        return self.identity.evidence_id

    @property
    def provider_name(self) -> str:
        return self.identity.provider_name

    @property
    def provider_platform(self) -> PlatformType:
        return self.identity.provider_platform

    @property
    def provider_type(self) -> ProviderType:
        return self.identity.provider_type

    @property
    def observation_key(self) -> str:
        return self.identity.observation_key

    @property
    def observed_at(self) -> datetime:
        return self.identity.observed_at

    @property
    def collected_at(self) -> datetime:
        return self.identity.collected_at

    @property
    def indicator_type(self) -> IndicatorType:
        return self.indicator.indicator_type

    @property
    def indicator_value(self) -> str:
        return self.indicator.indicator_value

    @property
    def indicator_source(self) -> IndicatorSource:
        return self.indicator.indicator_source

    @property
    def condition(self) -> ThreatCondition:
        return self.indicator.condition

    @property
    def severity(self) -> ThreatSeverity:
        return self.context.severity

    @property
    def confidence(self) -> ThreatConfidence:
        return self.context.confidence

    @property
    def provider_trust(self) -> ProviderTrustLevel:
        return self.context.provider_trust

    @property
    def expires_at(self) -> datetime | None:
        return self.context.expires_at

    # =========================================================================
    # Derived Properties
    # =========================================================================

    @property
    def age(self):
        """
        Return the age of the observation.
        """

        return utc_now() - self.observed_at

    @property
    def age_seconds(self) -> float:
        """
        Return the observation age in seconds.
        """

        return self.age.total_seconds()

    @property
    def is_expired(self) -> bool:
        """
        Return True if the evidence has expired.
        """

        if self.expires_at is None:
            return False

        return utc_now() >= self.expires_at

    @property
    def is_usable(self) -> bool:
        """
        Return True if the evidence is eligible for
        deterministic reasoning.
        """

        return not self.is_expired

    # =========================================================================
    # Matching Helpers
    # =========================================================================

    def matches_indicator(
        self,
        indicator: IndicatorType,
    ) -> bool:
        return self.indicator_type == indicator

    def matches_provider(
        self,
        provider_name: str,
    ) -> bool:
        return (
            self.provider_name.casefold()
            ==
            provider_name.casefold()
        )

    def matches_condition(
        self,
        condition: ThreatCondition,
    ) -> bool:
        return self.condition == condition

    def matches_platform(
        self,
        platform: PlatformType,
    ) -> bool:
        return self.provider_platform == platform

    def matches_tag(
        self,
        tag: str,
    ) -> bool:
        return tag in self.context.tags

    # =========================================================================
    # Description
    # =========================================================================

    def describe(self) -> str:
        """
        Return a concise human-readable description.
        """

        return (
            f"{self.provider_name} observed "
            f"{self.condition.value} "
            f"for "
            f"{self.indicator_value}"
        )

    # =========================================================================
    # Serialization
    # =========================================================================

    def to_dict(self) -> dict[str, Any]:
        """
        Convert ThreatEvidence into a serializable dictionary.

        Future versions may implement from_dict() and JSON
        serialization.
        """

        return {

            "identity": vars(self.identity),

            "indicator": vars(self.indicator),

            "source": vars(self.source),

            "context": {

                "severity":
                    self.context.severity.value,

                "confidence":
                    self.context.confidence.value,

                "provider_trust":
                    self.context.provider_trust.value,

                "expires_at":
                    (
                        self.context.expires_at.isoformat()
                        if self.context.expires_at
                        else None
                    ),

                "tags":
                    sorted(self.context.tags),

                "notes":
                    self.context.notes,

            },

        }


# =============================================================================
#
# Chewbacca's Commentary 🐾
#
# Engineers
#
# naturally want
#
# answers.
#
# Fusion
#
# asks for
#
# observations
#
# first.
#
# Every conclusion
#
# begins
#
# as evidence.
#
# Every investigation
#
# begins
#
# as curiosity.
#
# Great engineers
#
# never stop asking
#
# one simple question.
#
# "What do we actually know?"
#
# Everything else
#
# follows from there.
#
#                              — Chewbacca
#                                Chief Wookiee Architect
#
# =============================================================================
