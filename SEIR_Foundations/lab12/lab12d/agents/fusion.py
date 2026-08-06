#!/usr/bin/env python3

"""
===============================================================================

Gen2X Security Engineering Platform

Module:
    fusion.py

Agent:
    Fusion Agent

Part I:
    Evidence Collection

===============================================================================

Business Objective
-------------------------------------------------------------------------------

Security providers observe the world.

Fusion understands it.

Every provider specializes in collecting one type of information.

Examples include:

    • VirusTotal
    • Wiz
    • GuardDuty
    • Security Hub
    • AWS Inspector
    • GitHub Secret Scanning
    • Weak TLS Scanner
    • Internal Asset Inventory

Unfortunately...

Every provider also speaks a different language.

VirusTotal returns one schema.

GuardDuty returns another.

GitHub returns another.

Wiz returns another.

Fusion should never need to understand every API.

Instead, every provider translates its findings into one common evidence
model.

Fusion reasons about evidence.

Not provider implementations.

-------------------------------------------------------------------------------

Fusion Pipeline

                    Providers

                         │

        ┌────────────────┼────────────────┐

        ▼                ▼                ▼

   VirusTotal       GitHub        GuardDuty

        ▼                ▼                ▼

                ThreatEvidence

                        ▼

             EvidenceAggregator

                        ▼

             ThreatCorrelation

                        ▼

             ThreatClassifier

                        ▼

          ThreatAssessmentEngine

                        ▼

                ThreatSummary

                        ▼

                  report.py

-------------------------------------------------------------------------------

Responsibilities

Fusion intentionally separates investigation into three stages.

Part I

    Collect evidence.

Part II

    Reason about evidence.

Part III

    Communicate conclusions.

This file implements Part I.

Part I is responsible for:

    • Normalizing provider output

    • Preserving provider provenance

    • Recording observations

    • Validating evidence

    • Organizing evidence

Part I deliberately avoids:

    • Threat classification

    • Final severity calculation

    • Confidence calculation

    • Response recommendations

    • Executive reporting

Those responsibilities belong to later stages.

-------------------------------------------------------------------------------

Architectural Philosophy

Every provider answers one question.

"What did I observe?"

Fusion answers a different question.

"What does all of this mean?"

That separation allows providers to remain independent while Fusion
remains reusable.

New providers should never require Fusion to be rewritten.

Only new translators should be added.

-------------------------------------------------------------------------------

Example

Provider Output

        Wiz

            ↓

    Deprecated Library

            ↓

ThreatEvidence(
    provider="wiz",
    condition=ThreatCondition.DEPRECATED_LIBRARY,
    severity=ThreatSeverity.HIGH,
    confidence=ThreatConfidence.OBSERVED,
)

Provider Output

        GitHub

            ↓

Exposed Secret

            ↓

ThreatEvidence(
    provider="github",
    condition=ThreatCondition.TOKEN_EXPOSURE,
    severity=ThreatSeverity.CRITICAL,
    confidence=ThreatConfidence.VALIDATED,
)

Fusion now receives identical objects.

The provider no longer matters.

Only the evidence matters.

===============================================================================

Chewbacca's Commentary 🐾

Imagine interviewing witnesses.

One speaks English.

One speaks Japanese.

One speaks Klingon.

One speaks...

whatever printers speak.

Before detectives compare stories,
someone must translate them into
one common language.

That's exactly what Part I does.

Fusion doesn't care
where evidence came from.

Fusion cares
that every observation
arrives speaking
the same language.

Professional investigations
begin with organized evidence.

Not conclusions.

                                — Chewbacca
                                  Chief Wookiee Architect

===============================================================================
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from models.enums import (
    IndicatorSource,
    IndicatorType,
    ProviderStatus,
    ProviderTrustLevel,
    ThreatCondition,
    ThreatConfidence,
    ThreatSeverity,
)


# =============================================================================
# Shared Helpers
# =============================================================================


def utc_now() -> datetime:
    """
    Return the current timezone-aware UTC timestamp.

    Every evidence object within Gen2X should use UTC.

    Consistent timestamps make evidence easier to correlate across
    providers, cloud platforms, and geographic regions.
    """

    return datetime.now(timezone.utc)


# =============================================================================
# Chewbacca's Commentary 🐾
#
# Security investigations
# eventually become
#
# timelines.
#
# One minute
#
# may explain
#
# an entire incident.
#
# Bad timestamps
#
# create
#
# bad investigations.
#
# Computers
# don't naturally agree
# what time it is.
#
# Engineers
# make them agree.
#
# =============================================================================


# =============================================================================
# Threat Evidence
# =============================================================================


@dataclass(slots=True)
class ThreatEvidence:
    """
    Represents one normalized observation produced by one provider.

    ThreatEvidence answers one question:

        "What did this provider observe?"

    Every provider within Gen2X returns the same object.

    Providers collect.

    Fusion reasons.

    Reports communicate.

    Separating those responsibilities keeps the platform modular,
    extensible, and easier to maintain.
    """

    # -------------------------------------------------------------------------
    # Evidence Identity
    # -------------------------------------------------------------------------

    evidence_id: str = field(default_factory=lambda: str(uuid4()))

    # -------------------------------------------------------------------------
    # Provider Information
    # -------------------------------------------------------------------------

    provider_name: str = ""

    provider_status: ProviderStatus = ProviderStatus.UNKNOWN

    provider_trust: ProviderTrustLevel = ProviderTrustLevel.UNKNOWN

    # -------------------------------------------------------------------------
    # Indicator
    # -------------------------------------------------------------------------

    indicator_value: str = ""

    indicator_type: IndicatorType = IndicatorType.UNKNOWN

    indicator_source: IndicatorSource = IndicatorSource.UNKNOWN

    # -------------------------------------------------------------------------
    # Provider Observation
    # -------------------------------------------------------------------------

    condition: ThreatCondition = ThreatCondition.UNKNOWN

    severity: ThreatSeverity = ThreatSeverity.UNKNOWN

    confidence: ThreatConfidence = ThreatConfidence.UNKNOWN

    summary: str = ""

    # -------------------------------------------------------------------------
    # Time
    # -------------------------------------------------------------------------

    observed_at: datetime = field(default_factory=utc_now)

    expires_at: datetime | None = None

    # -------------------------------------------------------------------------
    # Provider Context
    # -------------------------------------------------------------------------

    metadata: dict[str, Any] = field(default_factory=dict)

    raw_reference: str | None = None

    # =========================================================================
    # Validation
    # =========================================================================

    def __post_init__(self) -> None:
        """
        Validate the structural integrity of the evidence object.

        Validation ensures consistency.

        It does not determine whether the provider is correct.
        """

        self.provider_name = self.provider_name.strip()
        self.indicator_value = self.indicator_value.strip()
        self.summary = self.summary.strip()

        if not self.provider_name:
            raise ValueError("provider_name cannot be empty")

        if not self.indicator_value:
            raise ValueError("indicator_value cannot be empty")

        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")

        if (
            self.expires_at is not None
            and self.expires_at <= self.observed_at
        ):
            raise ValueError(
                "expires_at must occur after observed_at"
            )

    # =========================================================================
    # Evidence State
    # =========================================================================

    @property
    def is_expired(self) -> bool:
        """Return True if the evidence has expired."""

        return (
            self.expires_at is not None
            and utc_now() >= self.expires_at
        )

    @property
    def provider_succeeded(self) -> bool:
        """Return True if the provider completed successfully."""

        return self.provider_status in {
            ProviderStatus.SUCCESS,
            ProviderStatus.PARTIAL_SUCCESS,
        }

    @property
    def is_usable(self) -> bool:
        """
        Determine whether this evidence may participate in analysis.

        Part II performs additional reasoning.

        Part I simply determines whether the evidence is structurally
        usable.
        """

        return (
            self.provider_succeeded
            and not self.is_expired
            and self.condition != ThreatCondition.UNKNOWN
        )

    # =========================================================================
    # Serialization
    # =========================================================================

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the evidence object into a JSON-serializable dictionary.
        """

        return {
            "evidence_id": self.evidence_id,
            "provider_name": self.provider_name,
            "provider_status": self.provider_status.value,
            "provider_trust": self.provider_trust.value,
            "indicator_value": self.indicator_value,
            "indicator_type": self.indicator_type.value,
            "indicator_source": self.indicator_source.value,
            "condition": self.condition.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "summary": self.summary,
            "observed_at": self.observed_at.isoformat(),
            "expires_at": (
                self.expires_at.isoformat()
                if self.expires_at
                else None
            ),
            "metadata": dict(self.metadata),
            "raw_reference": self.raw_reference,
        }


# =============================================================================
# Chewbacca's Commentary 🐾
#
# Every provider
# believes
# it is the center
# of the universe.
#
# It isn't.
#
# VirusTotal
# knows VirusTotal.
#
# Wiz
# knows Wiz.
#
# GitHub
# knows GitHub.
#
# GuardDuty
# knows GuardDuty.
#
# Fusion knows
#
# evidence.
#
# Great architectures
# don't force
# every component
# to speak
# the same language.
#
# They create
# a common language
# everyone shares.
#
# That's what
# ThreatEvidence
# becomes.
#
#                              — Chewbacca
#                                Chief Wookiee Architect
#
# =============================================================================

# =============================================================================
#
# Part II — Threat Reasoning
#
# =============================================================================
#
# Business Objective
# -----------------------------------------------------------------------------
#
# Part I collected evidence.
#
# Part II transforms that evidence into deterministic security analysis.
#
# Fusion intentionally separates reasoning into four independent stages.
#
#     Evidence Selection
#
#             ↓
#
#     Threat Correlation
#
#             ↓
#
#     Threat Classification
#
#             ↓
#
#     Threat Assessment
#
# Each stage answers one architectural question.
#
# This separation keeps Fusion explainable, testable, and easy to extend.
#
# Unlike many security products, Fusion intentionally avoids "magic scores."
#
# Every recommendation can be traced back to explicit evidence.
#
# =============================================================================

from dataclasses import dataclass, field
from uuid import uuid4

from models.enums import (
    ThreatAssessment,
    ThreatCondition,
    ThreatConfidence,
    ThreatDomain,
    ThreatSeverity,
    ThreatType,
)


# =============================================================================
# Assessment Result
# =============================================================================


@dataclass(slots=True)
class AssessmentResult:
    """
    Represents the deterministic conclusion produced by Fusion.

    AssessmentResult forms the contract between:

        Part II
            Threat Reasoning

    and

        Part III
            Threat Communication

    The object intentionally contains structured data rather than prose.

    Report generation and Bedrock explanations occur later.
    """

    assessment_id: str = field(default_factory=lambda: str(uuid4()))

    threat_type: ThreatType = ThreatType.UNKNOWN

    threat_domain: ThreatDomain = ThreatDomain.UNKNOWN

    conditions: list[ThreatCondition] = field(default_factory=list)

    severity: ThreatSeverity = ThreatSeverity.UNKNOWN

    confidence: ThreatConfidence = ThreatConfidence.UNKNOWN

    assessment: ThreatAssessment = ThreatAssessment.UNKNOWN

    rationale: list[str] = field(default_factory=list)

    supporting_evidence: list[ThreatEvidence] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Evidence Selector
# =============================================================================


class EvidenceSelector:
    """
    Select evidence eligible for deterministic reasoning.

    EvidenceSelector answers one question:

        "Which evidence deserves to participate?"

    Responsibilities
    ----------------

        ✓ Remove expired evidence

        ✓ Remove failed provider results

        ✓ Filter duplicate observations

        ✓ Apply minimum provider trust

        ✓ Group related evidence

    This class deliberately performs no threat analysis.
    """

    def select(
        self,
        aggregator: EvidenceAggregator,
    ) -> list[ThreatEvidence]:
        """
        Return evidence eligible for analysis.
        """

        usable = []

        for evidence in aggregator.usable():

            if evidence.provider_trust == ProviderTrustLevel.UNTRUSTED:
                continue

            usable.append(evidence)

        return usable


# =============================================================================
# Chewbacca's Commentary 🐾
#
# More evidence
#
# does not automatically mean
#
# better evidence.
#
# One verified observation
#
# is often worth more
#
# than twenty stale reports.
#
# Great investigations
#
# begin by deciding
#
# what deserves attention.
#
# =============================================================================


# =============================================================================
# Threat Correlation
# =============================================================================


@dataclass(slots=True)
class CorrelationGroup:
    """
    Represents evidence believed to belong to the same investigation.
    """

    correlation_id: str = field(default_factory=lambda: str(uuid4()))

    evidence: list[ThreatEvidence] = field(default_factory=list)

    rationale: list[str] = field(default_factory=list)


class ThreatCorrelation:
    """
    Correlate observations that appear related.

    ThreatCorrelation answers:

        "Which observations belong together?"

    Correlation identifies relationships.

    Correlation does not determine guilt.
    """

    def correlate(
        self,
        evidence: list[ThreatEvidence],
    ) -> list[CorrelationGroup]:
        """
        Produce correlation groups.

        Sample implementation.

        Students are encouraged to experiment with additional correlation
        strategies.
        """

        groups = []

        #
        # Placeholder implementation.
        #
        # Future labs may correlate by:
        #
        #   • Identity
        #   • Asset
        #   • Repository
        #   • Account
        #   • Time Window
        #   • Provider Agreement
        #

        return groups


# =============================================================================
# Chewbacca's Commentary 🐾
#
# Correlation
#
# explains
#
# relationships.
#
# It does not explain
#
# intent.
#
# Two events
#
# occurring together
#
# may simply have
#
# terrible timing.
#
# Engineers should always
#
# explain
#
# why evidence
#
# was grouped.
#
# =============================================================================


# =============================================================================
# Threat Classifier
# =============================================================================


class ThreatClassifier:
    """
    Translate correlated evidence into the Gen2X threat vocabulary.

    ThreatClassifier answers:

        "What kind of security problem
        best describes this investigation?"
    """

    CONDITION_TYPE_MAP = {

        ThreatCondition.UNUSED_ACCOUNT:
            ThreatType.IDENTITY_EXPOSURE,

        ThreatCondition.UNUSED_TOKEN:
            ThreatType.IDENTITY_EXPOSURE,

        ThreatCondition.TOKEN_EXPOSURE:
            ThreatType.IDENTITY_EXPOSURE,

        ThreatCondition.DEPRECATED_LIBRARY:
            ThreatType.VULNERABILITY_EXPOSURE,

        ThreatCondition.EXPOSED_ENDPOINT:
            ThreatType.MISCONFIGURATION,

    }

    CONDITION_DOMAIN_MAP = {

        ThreatCondition.UNUSED_ACCOUNT:
            ThreatDomain.IDENTITY,

        ThreatCondition.UNUSED_TOKEN:
            ThreatDomain.IDENTITY,

        ThreatCondition.TOKEN_EXPOSURE:
            ThreatDomain.IDENTITY,

        ThreatCondition.DEPRECATED_LIBRARY:
            ThreatDomain.APPLICATION,

        ThreatCondition.EXPOSED_ENDPOINT:
            ThreatDomain.API,

    }

    def classify(
        self,
        group: CorrelationGroup,
    ) -> tuple[ThreatType, ThreatDomain]:
        """
        Return the deterministic threat classification.

        Sample implementation.

        Future labs may extend these mapping tables without changing the
        Fusion architecture.
        """

        return (
            ThreatType.UNKNOWN,
            ThreatDomain.UNKNOWN,
        )


# =============================================================================
# Chewbacca's Commentary 🐾
#
# Classification
#
# gives evidence
#
# a name.
#
# Naming
#
# creates order.
#
# It does not create
#
# certainty.
#
# Classification
#
# is vocabulary.
#
# Assessment
#
# is judgment.
#
# =============================================================================


# =============================================================================
# Threat Assessment Engine
# =============================================================================


class ThreatAssessmentEngine:
    """
    Produce deterministic threat assessments.

    ThreatAssessmentEngine answers:

        • How severe?

        • How confident?

        • What recommendation?
    """

    def assess(
        self,
        group: CorrelationGroup,
    ) -> AssessmentResult:
        """
        Produce the deterministic assessment.

        Sample implementation.

        Future labs may implement organization-specific assessment
        policies here.
        """

        result = AssessmentResult()

        #
        # Example policy.
        #
        # Future assessment matrices may consider:
        #
        #   • Multiple provider agreement
        #   • Provider trust
        #   • Asset criticality
        #   • Internet exposure
        #   • Identity exposure
        #   • Secret exposure
        #   • Known exploitation
        #

        result.severity = ThreatSeverity.UNKNOWN

        result.confidence = ThreatConfidence.UNKNOWN

        result.assessment = ThreatAssessment.UNKNOWN

        return result


# =============================================================================
# Chewbacca's Commentary 🐾
#
# Dashboards
#
# love
#
# one score.
#
# Engineers
#
# shouldn't.
#
# Severity answers:
#
#     "How bad?"
#
# Confidence answers:
#
#     "How sure?"
#
# Assessment answers:
#
#     "What recommendation
#      is justified?"
#
# Three questions.
#
# Three answers.
#
# Keep them separate.
#
# Future-you,
#
# reviewing
# an incident
#
# at 2:17 AM,
#
# will appreciate
# the difference.
#
# =============================================================================

# =============================================================================
#
# Part III — Threat Communication
#
# =============================================================================
#
# Business Objective
# -----------------------------------------------------------------------------
#
# Part I organized evidence.
#
# Part II transformed evidence into deterministic engineering reasoning.
#
# Part III communicates those engineering conclusions without changing them.
#
# Fusion intentionally separates:
#
#     Engineering
#
# from
#
#     Presentation.
#
# Reports,
# dashboards,
# PDFs,
# Markdown,
# Slack notifications,
# Jira tickets,
# ServiceNow incidents,
# and AI-generated explanations
#
# are all communication mechanisms.
#
# None of them should alter the engineering conclusions produced by
# Part II.
#
# -----------------------------------------------------------------------------
#
# Communication Pipeline
#
#             AssessmentResult
#
#                     │
#
#                     ▼
#
#          ThreatSummaryBuilder
#
#                     │
#
#                     ▼
#
#              ThreatSummary
#
#                     │
#
# ────────────────────┼──────────────────────────────────────────────
#
#                     ▼
#
#             NarrativeAdapter
#
#                     │
#
# ────────────────────┼──────────────────────────────────────────────
#
#                     ▼
#
#             SummaryExporter
#
#        ┌────────────┼─────────────┐
#        ▼            ▼             ▼
#
#      JSON        Markdown        PDF
#
#        ▼            ▼             ▼
#
#     Slack        EventBridge     HTML
#
# -----------------------------------------------------------------------------
#
# Architectural Philosophy
#
# Communication should never modify engineering conclusions.
#
# It should only make them easier for humans to understand.
#
# Fusion produces structured understanding.
#
# Exporters determine presentation.
#
# =============================================================================


# =============================================================================
# Threat Summary
# =============================================================================


@dataclass(slots=True)
class ThreatSummary:
    """
    Represents the complete engineering summary produced by Fusion.

    ThreatSummary is the communication contract between Fusion and every
    downstream component.

    Report generators, AI services, dashboards, and notification systems all
    consume this object.

    None of those systems should modify the engineering conclusions.
    """

    summary_id: str = field(default_factory=lambda: str(uuid4()))

    title: str = ""

    executive_summary: str = ""

    assessment: AssessmentResult = field(
        default_factory=AssessmentResult
    )

    findings: list[str] = field(default_factory=list)

    recommendations: list[str] = field(default_factory=list)

    evidence_count: int = 0

    provider_count: int = 0

    generated_at: datetime = field(default_factory=utc_now)

    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Chewbacca's Commentary 🐾
#
# Reports
#
# come in
#
# many formats.
#
# PDFs.
#
# Dashboards.
#
# Slack.
#
# ServiceNow.
#
# Jira.
#
# Email.
#
# Engineers
#
# should never
#
# rewrite
#
# an investigation
#
# simply because
#
# someone requested
#
# another output format.
#
# Build
#
# one
#
# complete summary.
#
# Everything else
#
# becomes formatting.
#
# =============================================================================


# =============================================================================
# Threat Summary Builder
# =============================================================================


class ThreatSummaryBuilder:
    """
    Build a structured ThreatSummary.

    Responsibilities
    ----------------

        ✓ Organize assessment results

        ✓ Summarize findings

        ✓ Generate recommendations

        ✓ Count evidence

        ✓ Preserve engineering reasoning

    Does NOT

        • Generate PDFs

        • Generate Markdown

        • Send Slack notifications

        • Call Bedrock

        • Create Jira tickets
    """

    def build(
        self,
        assessment: AssessmentResult,
    ) -> ThreatSummary:
        """
        Construct the communication model.

        Sample implementation.

        Future labs may enrich this summary using organizational
        requirements while preserving the underlying engineering
        conclusions.
        """

        summary = ThreatSummary()

        summary.assessment = assessment

        summary.title = (
            f"{assessment.threat_type.value} Investigation"
        )

        summary.executive_summary = (
            "Deterministic threat assessment completed."
        )

        summary.findings = list(assessment.rationale)

        summary.recommendations = [
            assessment.assessment.describe()
            if hasattr(assessment.assessment, "describe")
            else assessment.assessment.value
        ]

        summary.evidence_count = len(
            assessment.supporting_evidence
        )

        summary.provider_count = len({
            evidence.provider_name
            for evidence in assessment.supporting_evidence
        })

        return summary


# =============================================================================
# Chewbacca's Commentary 🐾
#
# Fusion
#
# already knows
#
# what happened.
#
# This class
#
# simply prepares
#
# that understanding
#
# for humans.
#
# Communication
#
# should clarify.
#
# Never reinterpret.
#
# =============================================================================


# =============================================================================
# Narrative Adapter
# =============================================================================


class NarrativeAdapter:
    """
    Prepare deterministic engineering results for natural-language
    explanation.

    NarrativeAdapter does not perform analysis.

    It prepares prompts for language models after engineering has
    already reached a conclusion.

    Python determines.

    AI explains.
    """

    def create_prompt(
        self,
        summary: ThreatSummary,
    ) -> str:
        """
        Produce a prompt suitable for an LLM.

        The prompt contains engineering conclusions that should be
        explained rather than reconsidered.
        """

        return f"""
Explain the following engineering assessment.

Threat Type:
    {summary.assessment.threat_type.value}

Threat Domain:
    {summary.assessment.threat_domain.value}

Severity:
    {summary.assessment.severity.value}

Confidence:
    {summary.assessment.confidence.value}

Assessment:
    {summary.assessment.assessment.value}

Key Findings:

{chr(10).join(f'- {finding}' for finding in summary.findings)}

Produce an executive summary suitable for a security manager.

Do not modify the engineering conclusions.
"""


# =============================================================================
# Chewbacca's Commentary 🐾
#
# AI
#
# is an excellent
#
# communicator.
#
# It should never
#
# become
#
# the investigator.
#
# Fusion
#
# reaches
#
# the conclusion.
#
# AI
#
# explains
#
# the conclusion.
#
# That's assistance.
#
# Not delegation.
#
# =============================================================================


# =============================================================================
# Summary Exporter
# =============================================================================


class SummaryExporter:
    """
    Base class for all communication exporters.

    Exporters change presentation.

    They never change engineering meaning.

    Future implementations may include:

        • JSON

        • Markdown

        • PDF

        • HTML

        • Slack

        • EventBridge

        • ServiceNow

        • Jira

        • Teams

    Fusion remains completely independent from those implementations.
    """

    def export(
        self,
        summary: ThreatSummary,
    ) -> Any:
        """
        Export a ThreatSummary.

        Derived classes implement the desired presentation format.
        """

        raise NotImplementedError


# =============================================================================
#
# Architect's Reflection
#
# Fusion is not a reporting engine.
#
# Fusion is not an AI agent.
#
# Fusion is an engineering reasoning engine.
#
# Providers observe.
#
# Fusion understands.
#
# Reports explain.
#
# Engineers decide.
#
# Every stage exists to preserve engineering integrity while making
# complex security investigations easier to understand.
#
# Communication should improve understanding.
#
# It should never change truth.
#
# The platform recommends.
#
# Accountability remains human.
#
#                              — Chewbacca
#                                Chief Wookiee Architect
#
# =============================================================================
