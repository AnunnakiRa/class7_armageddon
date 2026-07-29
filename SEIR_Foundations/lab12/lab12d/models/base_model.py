"""
===============================================================================
 Gen2X Security Engineering Platform

 Module: base_model.py

 Description:
 ------------
 This module defines the BaseModel used throughout the Gen2X platform.

 Every domain model inherits from BaseModel.

 Examples include:

     • Indicator
     • ProviderResult
     • ThreatEvidence
     • ThreatSummary
     • Finding
     • Recommendation
     • ThreatIntelligenceReport

 BaseModel provides only common functionality shared by every model.

 It intentionally contains NO business logic.

 Responsibilities
 ----------------

 ✔ Serialization
 ✔ Deserialization
 ✔ JSON Conversion
 ✔ Dictionary Conversion
 ✔ Object Copying
 ✔ Validation Hooks
 ✔ Debug Representation

 Non-Responsibilities
 --------------------

 ✘ Threat Intelligence
 ✘ AWS
 ✘ Provider Logic
 ✘ HTTP
 ✘ Databases
 ✘ Risk Scoring
 ✘ AI
 ✘ Report Generation

 Educational Notes
 -----------------

 One goal of Gen2X is teaching enterprise software architecture.

 Rather than repeatedly implementing utility functions inside every
 domain model, BaseModel centralizes common behavior.

 This allows students to focus on the domain itself rather than
 boilerplate code.

===============================================================================
"""

from __future__ import annotations

import copy
import json
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import fields
from dataclasses import is_dataclass
from typing import Any
from typing import Dict
from typing import Type
from typing import TypeVar

# ============================================================================
# Generic Type Variable
# ============================================================================

T = TypeVar("T", bound="BaseModel")


# ============================================================================
# Base Model
# ============================================================================

@dataclass
class BaseModel:
    """
    Base class for every Gen2X domain model.

    Why does this class exist?

    Enterprise software commonly contains hundreds of domain models.

    Without a common base class every model would need to implement:

        • to_dict()
        • to_json()
        • from_dict()
        • copy()
        • validation
        • debugging

    individually.

    BaseModel centralizes those capabilities while remaining completely
    independent of the security domain.

    This class should remain generic.

    If a method is specific to Threat Intelligence,
    Providers,
    AWS,
    Reporting,
    or Fusion,

    it DOES NOT belong here.
    """

    # ----------------------------------------------------------------------
    # Lifecycle Hook
    # ----------------------------------------------------------------------

    def __post_init__(self) -> None:
        """
        Automatically validate every model after construction.

        Dataclasses automatically call __post_init__()
        after __init__() completes.

        Child classes may override validate()
        without overriding __post_init__().
        """
        self.validate()

    # ----------------------------------------------------------------------
    # Validation Hook
    # ----------------------------------------------------------------------

    def validate(self) -> None:
        """
        Validation hook.

        Child models override this method
        to implement custom validation.

        Example

            class Indicator(BaseModel):

                def validate(self):

                    if not self.value:
                        raise ValueError("Indicator cannot be empty")

        The default implementation performs no validation.
        """
        return

    # ----------------------------------------------------------------------
    # Dictionary Serialization
    # ----------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert this dataclass into a dictionary.

        Nested dataclasses are automatically converted.

        Returns
        -------
        dict
        """
        return asdict(self)

    # ----------------------------------------------------------------------
    # JSON Serialization
    # ----------------------------------------------------------------------

    def to_json(self, indent: int = 4) -> str:
        """
        Serialize this model into JSON.

        Parameters
        ----------
        indent
            Number of spaces used for formatting.

        Returns
        -------
        str
        """

        return json.dumps(
            self.to_dict(),
            indent=indent,
            default=str,
            sort_keys=True,
        )

    # ----------------------------------------------------------------------
    # Deserialization
    # ----------------------------------------------------------------------

    @classmethod
    def from_dict(cls: Type[T], data: Dict[str, Any]) -> T:
        """
        Construct an object from a dictionary.

        Unknown fields are ignored.

        Missing required fields will raise
        the normal dataclass exception.

        Returns
        -------
        BaseModel
        """

        valid_fields = {field.name for field in fields(cls)}

        filtered = {
            key: value
            for key, value in data.items()
            if key in valid_fields
        }

        return cls(**filtered)

    # ----------------------------------------------------------------------
    # Object Copy
    # ----------------------------------------------------------------------

    def copy(self: T) -> T:
        """
        Create a deep copy of this object.

        Returns
        -------
        BaseModel
        """
        return copy.deepcopy(self)

    # ----------------------------------------------------------------------
    # Pretty Representation
    # ----------------------------------------------------------------------

    def __repr__(self) -> str:
        """
        Human-friendly representation.

        Useful while debugging.

        Example

            ProviderResult(
                provider='AbuseIPDB',
                status='SUCCESS'
            )
        """

        values = ", ".join(

            f"{field.name}={getattr(self, field.name)!r}"

            for field in fields(self)

        )

        return f"{self.__class__.__name__}({values})"

    # ----------------------------------------------------------------------
    # Equality Helper
    # ----------------------------------------------------------------------

    def equals(self, other: object) -> bool:
        """
        Compare two models.

        This is equivalent to == but
        reads more naturally for some students.
        """

        return self == other

    # ----------------------------------------------------------------------
    # Utility
    # ----------------------------------------------------------------------

    @property
    def model_name(self) -> str:
        """
        Returns the class name.

        Example

            Indicator

            ThreatSummary

            Recommendation
        """

        return self.__class__.__name__

    # ----------------------------------------------------------------------
    # Utility
    # ----------------------------------------------------------------------

    @property
    def is_valid(self) -> bool:
        """
        Indicates whether validation succeeds.

        Useful for demonstrations and testing.

        Returns
        -------
        bool
        """

        try:

            self.validate()

            return True

        except Exception:

            return False

    # ----------------------------------------------------------------------
    # Utility
    # ----------------------------------------------------------------------

    @property
    def field_names(self) -> list[str]:
        """
        Return every dataclass field name.
        """

        return [field.name for field in fields(self)]

    # ----------------------------------------------------------------------
    # Utility
    # ----------------------------------------------------------------------

    def field_count(self) -> int:
        """
        Return the number of dataclass fields.
        """

        return len(fields(self))
