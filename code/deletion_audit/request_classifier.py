import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class AuthorizationStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    UNCERTAIN = "UNCERTAIN"


class RequestIntent(str, Enum):
    DELETION = "DELETION"
    ACCESS = "ACCESS"
    CORRECTION = "CORRECTION"
    EXPORT = "EXPORT"
    MARKETING_OPTOUT = "MARKETING_OPTOUT"
    OTHER = "OTHER"


class SignalPolarity(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATED = "NEGATED"
    MENTIONED = "MENTIONED"


@dataclass(frozen=True)
class IntentSignal:
    intent: RequestIntent
    polarity: SignalPolarity
    matched_text: str


@dataclass(frozen=True)
class RequestClassification:
    authorization: AuthorizationStatus
    intents: Tuple[RequestIntent, ...]
    signals: Tuple[IntentSignal, ...]
    uncertainty_reasons: Tuple[str, ...]


_DELETE_PATTERNS = (
    re.compile(
        r"\b(?:delet(?:e|ed|ing|ion|ions)|eras(?:e|ed|ing|ure)|"
        r"remov(?:e|ed|ing|al)|wip(?:e|ed|ing)|purge(?:d|s|ing)?|"
        r"forget(?:ting|s)?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:elimin\w*|borr\w*|suprim\w*|exclu\w*|apag\w*|"
        r"remov\w*|supprim\w*|suppres\w*|effac\w*|clotur\w*)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bclos(?:e|ed|ing)\b.{0,32}\b(?:account|profile|membership)\b", re.IGNORECASE),
    re.compile(r"\b(?:account|profile|membership)\b.{0,32}\bclos(?:ed|ure)\b", re.IGNORECASE),
    re.compile(r"\u524a\u9664|\u6d88\u53bb|\u62b9\u6d88|\u9000\u4f1a"),
    re.compile(r"\uc0ad\uc81c|\uc81c\uac70|\ud0c8\ud1f4"),
)

_NEGATED_DELETE_PATTERNS = (
    re.compile(
        r"\bi(?:['’]m| am)\s+not\s+(?:permanently\s+)?"
        r"(?:delet\w*|eras\w*|remov\w*|wip\w*|purg\w*|clos\w*)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:do not|don['’]?t|never)\s+(?:(?:want|wish|need|request|"
        r"ask(?:ing)?(?:\s+for)?|seeking)\s+)?(?:to\s+)?"
        r"(?:\w+\s+){0,3}(?:delet\w*|eras\w*|remov\w*|wip\w*|"
        r"purg\w*|forget\w*|clos\w*)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bnot\s+(?:requesting|asking\s+for|seeking)\s+"
        r"(?:an?\s+)?(?:account\s+)?(?:deletion|erasure|removal)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bwithout\s+(?:permanently\s+)?(?:delet\w*|eras\w*|remov\w*|"
        r"wip\w*|purg\w*)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:no\s+quiero|no\s+solicito|no\s+pido)\b"
        r"(?:\s+\w+){0,4}\s+(?:elimin\w*|borr\w*|suprim\w*|exclu\w*|apag\w*)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bne\s+(?:veux|souhaite|demande)\s+pas\b"
        r"(?:\s+\w+){0,4}\s+(?:supprim\w*|effac\w*|clotur\w*)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bnao\s+(?:quero|solicito|peco)\b"
        r"(?:\s+\w+){0,4}\s+(?:exclu\w*|apag\w*|remov\w*|elimin\w*)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\u524a\u9664\u3057\u306a\u3044|\u524a\u9664\u3092\u5e0c\u671b\u3057\u307e\u305b\u3093"),
    re.compile(r"\uc0ad\uc81c\ud558\uc9c0\s*\ub9d0|\uc0ad\uc81c\ub97c\s*\uc6d0\ud558\uc9c0\s*\uc54a"),
)

_REQUEST_FRAME_PATTERN = re.compile(
    r"\b(?:please|i\s+(?:want|would\s+like|request(?:ing)?|need|am\s+asking)|"
    r"\bi\s+am\s+requesting|"
    r"\bi(?:['’]m| am)\s+(?:delet\w*|eras\w*|remov\w*)|"
    r"would\s+like\s+(?:(?:it|my\s+(?:account|profile|data))\s+)?"
    r"(?:permanently\s+)?(?:delet\w*|eras\w*|remov\w*)|"
    r"i['’]d\s+like|i['’]m\s+asking|can\s+you|could\s+you|"
    r"treat\s+this\s+message\s+as\s+a\s+request|"
    r"solicito|solicite|quiero|pido|intente|por\s+favor|"
    r"je\s+demande|je\s+souhaite|je\s+veux|veuillez)\b|"
    r"\u4f9d\u983c|\u304a\u9858\u3044\u3057\u307e\u3059|"
    r"\u304f\u3060\u3055\u3044|\uc694\uccad|\uc8fc\uc138\uc694",
    re.IGNORECASE,
)
_NON_REQUESTING_HELP_PATTERN = re.compile(
    r"\b(?:how\s+(?:do|can|could)\s+i|what\s+does|meaning\s+of|"
    r"explain)\b",
    re.IGNORECASE,
)
_DELETION_TARGET_PATTERN = re.compile(
    r"\b(?:account|profile|membership|personal\s+data|personal\s+"
    r"information|my\s+data|my\s+details|my\s+records|name|"
    r"contact\s+details|cuenta|perfil|datos|compte|profil|donnees|"
    r"conta|dados)\b",
    re.IGNORECASE,
)

_STATUS_QUERY_PATTERNS = (
    re.compile(
        r"\b(?:verify|check|inspect|audit|confirm|tell\s+me|find\s+out)\b"
        r".{0,100}\b(?:delet\w*|eras\w*|remov\w*|gone|no\s+longer\s+"
        r"(?:exist|appear|remain))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:delet\w*|eras\w*|remov\w*|gone)\b.{0,80}\b"
        r"(?:verify|check|inspect|audit|confirm|request|review)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\u524a\u9664|\uc0ad\uc81c"),
)

_NONDELETION_PATTERNS = {
    RequestIntent.ACCESS: (
        re.compile(
            r"\b(?:access|view|see|obtain|get|request)\b.{0,40}\b"
            r"(?:my|the)?\s*(?:personal\s+)?(?:data|information|records|account\s+information)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:copy\s+of|download\s+my)\b.{0,30}\b"
            r"(?:data|information|records|invoices)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:acceso|acceder|consulter|acces)\b.{0,40}\b(?:datos|donnees|information)\b", re.IGNORECASE),
        re.compile(r"\u958b\u793a|\u95b2\u89a7|\u95b2\u89a7|\uc5f4\ub78c|\uc811\uadfc"),
    ),
    RequestIntent.CORRECTION: (
        re.compile(
            r"\b(?:correct|correction|update|change|fix|replace|"
            r"corrig\w*|rectifi\w*|modifi\w*|actualiz\w*)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\uc815\uc815|\uc218\uc815|\ubcc0\uacbd"),
        re.compile(r"\u4fee\u6b63|\u8a02\u6b63|\u66f4\u65b0"),
    ),
    RequestIntent.EXPORT: (
        re.compile(r"\b(?:export|download|exportar|descarg\w*|telecharger)\b", re.IGNORECASE),
        re.compile(r"\u30c0\u30a6\u30f3\u30ed\u30fc\u30c9|\u30a8\u30af\u30b9\u30dd\u30fc\u30c8"),
        re.compile(r"\ub2e4\uc6b4\ub85c\ub4dc|\ub0b4\ubcf4\ub0b4\uae30"),
    ),
    RequestIntent.MARKETING_OPTOUT: (
        re.compile(
            r"\b(?:opt[\s-]?out|unsubscribe|stop\s+(?:sending|receiving)|"
            r"no\s+longer\s+receive|remove\s+me\s+from\s+(?:the\s+)?"
            r"marketing\s+lists?|marketing\s+preferences|"
            r"promotional\s+emails?|advertising\s+emails?)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:desabonar|desinscrever|desabonnement|desinscription)\w*\b", re.IGNORECASE),
        re.compile(r"\u914d\u4fe1\u505c\u6b62|\uc218\uc2e0\uac70\ubd80|\ub9c8\ucf00\ud305|\u5e83\u544a"),
    ),
    RequestIntent.OTHER: (
        re.compile(
            r"\b(?:reset|recover|unlock)\b.{0,35}\b(?:password|login|account access)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:how\s+(?:do|can|could)\s+i|what\s+does|explain)\b"
            r".{0,50}\b(?:delet\w*|eras\w*|remov\w*)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u30ea\u30bb\u30c3\u30c8|\ube44\ubc00\ubc88\ud638"),
    ),
}


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text).casefold()
    without_accents = "".join(
        character for character in normalized
        if not unicodedata.combining(character)
    )
    return unicodedata.normalize("NFC", without_accents).replace("’", "'")


def _has_deletion_request_frame(text: str, start: int, end: int) -> bool:
    left = max(text.rfind(".", 0, start), text.rfind("!", 0, start), text.rfind("?", 0, start), text.rfind(";", 0, start)) + 1
    ends = [
        position
        for position in (
            text.find(".", end),
            text.find("!", end),
            text.find("?", end),
            text.find(";", end),
        )
        if position >= 0
    ]
    right = min(ends) if ends else len(text)
    clause = text[left:right]
    if _NON_REQUESTING_HELP_PATTERN.search(clause):
        return False
    if _REQUEST_FRAME_PATTERN.search(clause):
        return True
    return _DELETION_TARGET_PATTERN.search(text) is not None and re.search(
        r"\b(?:please\s+)?(?:delete|erase|remove|wipe|purge|"
        r"elimin\w*|borr\w*|suprim\w*|exclu\w*|apag\w*|"
        r"supprim\w*|effac\w*|clos\w*)\b",
        clause,
        re.IGNORECASE,
    ) is not None


def _find_signals(text: str) -> Tuple[List[IntentSignal], bool]:
    normalized = _normalize(text)
    negated_matches = [
        match
        for pattern in _NEGATED_DELETE_PATTERNS
        for match in pattern.finditer(normalized)
    ]
    signals = []
    positive_deletion = False
    negated_deletion = bool(negated_matches)

    for pattern in _DELETE_PATTERNS:
        for match in pattern.finditer(normalized):
            if any(
                negated.start() <= match.start() < negated.end()
                for negated in negated_matches
            ):
                continue
            matched = normalized[match.start() : match.end()]
            if _is_marketing_removal(normalized, match.start(), match.end()):
                continue
            if not _has_deletion_request_frame(
                normalized, match.start(), match.end()
            ):
                signals.append(
                    IntentSignal(
                        RequestIntent.DELETION,
                        SignalPolarity.MENTIONED,
                        normalized[match.start() : match.end()],
                    )
                )
                continue
            positive_deletion = True
            signals.append(
                IntentSignal(RequestIntent.DELETION, SignalPolarity.POSITIVE, matched)
            )

    if negated_deletion:
        for match in negated_matches:
            signals.append(
                IntentSignal(
                    RequestIntent.DELETION,
                    SignalPolarity.NEGATED,
                    normalized[match.start() : match.end()],
                )
            )

    if not positive_deletion:
        for pattern in _STATUS_QUERY_PATTERNS:
            match = pattern.search(normalized)
            if match is not None and _is_audit_request(normalized):
                positive_deletion = True
                signals.append(
                    IntentSignal(
                        RequestIntent.DELETION,
                        SignalPolarity.POSITIVE,
                        normalized[match.start() : match.end()],
                    )
                )
                break

    for intent, patterns in _NONDELETION_PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(normalized)
            if match is not None:
                signals.append(
                    IntentSignal(
                        intent,
                        SignalPolarity.POSITIVE,
                        normalized[match.start() : match.end()],
                    )
                )
                break

    return signals, negated_deletion


def _is_marketing_removal(text: str, start: int, end: int) -> bool:
    context = text[max(0, start - 10) : min(len(text), end + 60)]
    return re.search(
        r"\b(?:email|emails|newsletter|mailing\s+list|marketing|"
        r"promotional|advertising)\b",
        context,
        re.IGNORECASE,
    ) is not None and re.search(
        r"\b(?:unsubscribe|opt[\s-]?out|stop\s+receiving|"
        r"remove\s+me\s+from|no\s+longer\s+receive)\b",
        context,
        re.IGNORECASE,
    ) is not None


def _is_audit_request(text: str) -> bool:
    return re.search(
        r"\b(?:verify|check|inspect|audit|confirm|review|tell\s+me|"
        r"find\s+out|please\s+report)\b",
        text,
        re.IGNORECASE,
    ) is not None


def classify_request(request_text: str) -> RequestClassification:
    """Classify authorization conservatively; uncertainty is not authorization."""
    if not isinstance(request_text, str) or not request_text.strip():
        return RequestClassification(
            AuthorizationStatus.UNCERTAIN,
            tuple(),
            tuple(),
            ("EMPTY_OR_INVALID_REQUEST_TEXT",),
        )

    signals, has_negated_deletion = _find_signals(request_text)
    positive_deletion = any(
        signal.intent == RequestIntent.DELETION
        and signal.polarity == SignalPolarity.POSITIVE
        for signal in signals
    )
    intents = tuple(
        intent
        for intent in RequestIntent
        if any(signal.intent == intent for signal in signals)
    )

    if positive_deletion and has_negated_deletion:
        authorization = AuthorizationStatus.UNCERTAIN
        reasons = ("CONFLICTING_DELETION_INTENT",)
    elif positive_deletion:
        authorization = AuthorizationStatus.AUTHORIZED
        reasons = tuple()
    elif has_negated_deletion or any(
        signal.intent != RequestIntent.DELETION for signal in signals
    ):
        authorization = AuthorizationStatus.NOT_AUTHORIZED
        reasons = tuple()
    else:
        authorization = AuthorizationStatus.UNCERTAIN
        reasons = (
            "DELETION_INTENT_NOT_ESTABLISHED"
            if signals
            else "NO_RECOGNIZED_REQUEST_INTENT",
        )

    return RequestClassification(
        authorization=authorization,
        intents=intents,
        signals=tuple(signals),
        uncertainty_reasons=reasons,
    )
