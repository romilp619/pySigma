from dataclasses import dataclass
from typing import ClassVar, Iterator
from sigma.modifiers import (
    SigmaContainsModifier,
    SigmaEndswithModifier,
    SigmaStartswithModifier,
)
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaExpansion, SigmaString, SigmaType, SpecialChars
from sigma.validators.base import (
    SigmaDetectionItemValidator,
    SigmaStringValueValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class DoubleWildcardIssue(SigmaValidationIssue):
    description: ClassVar[str] = "String contains multiple consecutive * wildcards"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string: SigmaString


class DoubleWildcardValidator(SigmaStringValueValidator):
    """Check strings for consecutive multi-character wildcards."""

    def validate_string(self, value: SigmaString) -> list[SigmaValidationIssue]:
        prev_wildcard = False
        for c in value.s:
            if c == SpecialChars.WILDCARD_MULTI:
                if prev_wildcard:  # previous character was also a wildcard
                    return [DoubleWildcardIssue([self.rule], value)]
                else:
                    prev_wildcard = True
            else:
                prev_wildcard = False
        return []


@dataclass
class NumberAsStringIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A number was expressed as string"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string: SigmaString


class NumberAsStringValidator(SigmaStringValueValidator):
    """Check numbers that were expressed as strings."""

    def validate_string(self, value: SigmaString) -> list[SigmaValidationIssue]:
        if len(value.s) == 1 and isinstance(value.s[0], str) and not " " in value.s[0]:
            try:
                int(value.s[0])
                return [NumberAsStringIssue([self.rule], value)]
            except ValueError:
                pass
        return []


@dataclass
class ControlCharacterIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String contains control character likely caused by missing (double-)slash"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    string: SigmaString


class ControlCharacterValidator(SigmaStringValueValidator):
    """
    Check for control characters in string values, which are normally inserted unintentionally by
    wrong usage of single backslashes, e.g. before a t character, where double backslashes are required.
    """

    def validate_string(self, value: SigmaString) -> list[SigmaValidationIssue]:
        if any((ord(c) < 32 for s in value.s for c in (s if isinstance(s, str) else ""))):
            return [ControlCharacterIssue([self.rule], value)]
        else:
            return []


@dataclass
class WildcardsInsteadOfContainsModifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String contains wildcards at beginning and end instead of being modified with contains modifier"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem


@dataclass
class WildcardInsteadOfStartswithIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String contains wildcard at end instead of being modified with startswith modifier"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem


@dataclass
class WildcardInsteadOfEndswithIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String contains wildcard at beginning instead of being modified with endswith modifier"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem


class WildcardsInsteadOfModifiersValidator(SigmaDetectionItemValidator):
    """Check if wildcards were used where usage of startswith, endswith and contains modifiers would be possible."""

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> list[SigmaValidationIssue]:
        # Warning rule use a single '*' waiting for the `exists` modifier  so check len(value)>1 to allow it
        if (
            detection_item.original_value is not None
            and all(
                (
                    isinstance(value, SigmaString)
                    and len(value) > 1
                    and value.startswith(SpecialChars.WILDCARD_MULTI)
                    and value.endswith(SpecialChars.WILDCARD_MULTI)
                    and not value[1:-1].contains_special()
                    for value in detection_item.original_value
                )
            )
            and SigmaContainsModifier not in detection_item.modifiers
        ):
            return [WildcardsInsteadOfContainsModifierIssue([self.rule], detection_item)]
        elif (
            detection_item.original_value is not None
            and all(
                (
                    isinstance(value, SigmaString)
                    and len(value) > 1
                    and value.startswith(SpecialChars.WILDCARD_MULTI)
                    and not value[1:].contains_special()
                    for value in detection_item.original_value
                )
            )
            and SigmaEndswithModifier not in detection_item.modifiers
        ):
            return [WildcardInsteadOfEndswithIssue([self.rule], detection_item)]
        elif (
            detection_item.original_value is not None
            and all(
                (
                    isinstance(value, SigmaString)
                    and len(value) > 1
                    and value.endswith(SpecialChars.WILDCARD_MULTI)
                    and not value[:-1].contains_special()
                    for value in detection_item.original_value
                )
            )
            and SigmaStartswithModifier not in detection_item.modifiers
        ):
            return [WildcardInsteadOfStartswithIssue([self.rule], detection_item)]
        else:
            return []


@dataclass
class EscapedWildcardIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule contains an escaped wildcard in the rule logic. Make sure the escape is intentional."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string: SigmaString


class EscapedWildcardValidator(SigmaStringValueValidator):
    """Check for the presence of escaped wildcards."""

    wildcard_list = ["*", "?"]

    def validate_string(self, value: SigmaString) -> list[SigmaValidationIssue]:
        if any([x in s for x in self.wildcard_list for s in value.s if isinstance(s, str)]):
            return [EscapedWildcardIssue([self.rule], value)]
        else:
            return []


# Partial-match modifiers turn an empty value or a single path separator into a match
# against almost every Windows or Unix path.
_PARTIAL_MATCH_MODIFIERS = (
    SigmaContainsModifier,
    SigmaEndswithModifier,
    SigmaStartswithModifier,
)
_TAUTOLOGICAL_LITERALS = frozenset(("", "\\", "/"))


def _iter_strings(value: SigmaType) -> Iterator[SigmaString]:
    """Yield strings contained in a value, including strings nested in expansions."""
    if isinstance(value, SigmaString):
        yield value
    elif isinstance(value, SigmaExpansion):
        for item in value.values:
            yield from _iter_strings(item)


def _plain_literal(value: SigmaString) -> str | None:
    """Return literal characters, ignoring wildcards.

    Placeholders make the matched text unknown, so those values are skipped.
    """
    parts: list[str] = []
    for part in value.s:
        if isinstance(part, str):
            parts.append(part)
        elif isinstance(part, SpecialChars):
            continue
        else:
            return None
    return "".join(parts)


def _is_unmodified_tautology(value: SigmaString) -> bool:
    """True when escape parsing leaves an empty string or exactly one path separator."""
    if any(not isinstance(part, str) for part in value.s):
        return False
    return _plain_literal(value) in _TAUTOLOGICAL_LITERALS


def _without_partial_match_wildcards(
    value: SigmaString, detection_item: SigmaDetectionItem
) -> list[str] | None:
    """Literal parts after dropping wildcards added by contains, startswith or endswith.

    Returns None when a placeholder or an author wildcard remains. Those values are not
    an empty string or a single path separator.
    """
    parts: list[str | SpecialChars] = []
    for part in value.s:
        if isinstance(part, (str, SpecialChars)):
            parts.append(part)
        else:
            return None
    modifiers = detection_item.modifiers
    if (
        (SigmaContainsModifier in modifiers or SigmaEndswithModifier in modifiers)
        and parts
        and parts[0] == SpecialChars.WILDCARD_MULTI
    ):
        del parts[0]
    if (
        (SigmaContainsModifier in modifiers or SigmaStartswithModifier in modifiers)
        and parts
        and parts[-1] == SpecialChars.WILDCARD_MULTI
    ):
        del parts[-1]
    if any(not isinstance(part, str) for part in parts):
        return None
    return [part for part in parts if isinstance(part, str)]


@dataclass
class EmptyOrPathSeparatorIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "contains, startswith or endswith is empty or one separator and matches nearly all values"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    string: SigmaString


class EmptyOrPathSeparatorValidator(SigmaDetectionItemValidator):
    """Flag contains, startswith and endswith values that match almost everything.

    SigmaString parses a pair of backslashes into one literal backslash. Combined with
    contains, startswith or endswith, that value matches almost every Windows path, and a
    single slash does the same for slash-separated paths. An empty string matches every
    value. Exact matches and longer fragments such as ``\\Users\\`` are not reported.
    Modifiers that rewrite the value first, such as base64 or wide, are ignored, because
    the matched text is no longer a path separator. Negated values are not reported,
    because they do not match everything.
    """

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> list[SigmaValidationIssue]:
        if detection_item.negated or not any(
            modifier in detection_item.modifiers for modifier in _PARTIAL_MATCH_MODIFIERS
        ):
            return []
        if detection_item.original_value is None:
            return self._validate_without_original(detection_item)

        final_literals = {
            literal
            for value in detection_item.value
            for string in _iter_strings(value)
            if (literal := _plain_literal(string)) is not None
        }
        issues: list[SigmaValidationIssue] = []
        for value in detection_item.original_value:
            if not isinstance(value, SigmaString) or not _is_unmodified_tautology(value):
                continue
            # Rewriting modifiers replace the author value. Report it only when a matched
            # literal is still empty or that same single separator.
            if _plain_literal(value) not in final_literals:
                continue
            issues.append(EmptyOrPathSeparatorIssue([self.rule], value))
        return issues

    def _validate_without_original(
        self, detection_item: SigmaDetectionItem
    ) -> list[SigmaValidationIssue]:
        """Check values after modifiers when the pre-modifier copy is no longer available."""
        issues: list[SigmaValidationIssue] = []
        for value in detection_item.value:
            for string in _iter_strings(value):
                parts = _without_partial_match_wildcards(string, detection_item)
                if parts is None:
                    continue
                literal = "".join(parts)
                if literal not in _TAUTOLOGICAL_LITERALS:
                    continue
                reduced = SigmaString()
                reduced.s = list(parts)
                issues.append(EmptyOrPathSeparatorIssue([self.rule], reduced))
        return issues
