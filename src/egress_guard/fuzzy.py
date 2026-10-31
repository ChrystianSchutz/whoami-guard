"""Fuzzy forms of the user's identity and e-mails in "contact" fields.

Two checks that run next to the exact scanner in scan.py; both report a finding that the hook turns into an `ask`
(the user decides) unless identity.json says otherwise:

* look-alike spellings of the user's name and e-mail that are not encodings but other ways to write the same thing:
  Unicode look-alikes (Cyrillic/Greek letters, full-width, zero-width characters), German/Polish transliteration
  (Müller / Mueller, Schmidt / Szmit, Christian / Krystian), digits for letters (Mu11er) and one or two typos.
* any e-mail address (anyone's, not only the user's) in a field whose job is to say who is calling: User-Agent,
  From, git -c user.email, `email=` / `contact=` parameters. An agent asked by a site for "a contact in the
  User-Agent" fills it with whatever address it knows, and that is the user's, so it gets a question first.

No ciphers: something built to hide (rot13, hex, a custom code) is out of scope for a pattern matcher.
"""
import re
import unicodedata
from urllib.parse import unquote_plus

# letters that look like Latin ones (Cyrillic, Greek); NFKC already maps full-width and mathematical letters
_CONFUSABLE = str.maketrans({
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y",
    "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S", "Ԁ": "D", "Һ": "H",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X",
    "ł": "l", "Ł": "L", "ø": "o", "Ø": "O", "ß": "ss", "đ": "d", "Đ": "D", "æ": "ae", "Æ": "AE", "œ": "oe",
    "Œ": "OE", "ı": "i",
})
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s"})
_GERMAN = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "Ä": "AE", "Ö": "OE", "Ü": "UE"})


def clean(s: str) -> str:
    """Unicode look-alikes to Latin, zero-width and other invisible format characters removed, diacritics removed,
    case kept (so word boundaries such as 'JanKowalski' survive)."""
    s = unicodedata.normalize("NFKC", s)
    s = "".join(c for c in s if unicodedata.category(c) != "Cf").translate(_CONFUSABLE)
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c))


# transliteration to one sound key, longest rules first: the same key for Müller / Mueller / Muller,
# Schmidt / Szmit / Shmit, Christian / Krystian, Wiśniewski / Wisniewski / Visnievski
_RULES = [
    ("tsch", "c"), ("sch", "s"), ("chr", "kr"), ("szcz", "sc"), ("ch", "h"), ("sz", "s"), ("sh", "s"), ("cz", "c"),
    ("tz", "c"), ("ts", "c"), ("ck", "k"), ("ph", "f"), ("th", "t"), ("dt", "t"), ("rz", "z"), ("ue", "u"),
    ("oe", "o"), ("ae", "a"), ("ie", "i"), ("w", "v"), ("y", "i"), ("q", "k"), ("x", "ks"),
]
_RULE_RE = re.compile("|".join(re.escape(a) for a, _ in _RULES))
_RULE_MAP = dict(_RULES)


def key(word: str) -> str:
    """Sound key of one word: lower case, German umlauts spelled out first (ü -> ue), then transliteration rules,
    double letters collapsed."""
    w = clean(word.translate(_GERMAN)).lower()
    w = _RULE_RE.sub(lambda m: _RULE_MAP[m.group(0)], w)
    return re.sub(r"(.)\1+", r"\1", w)


def osa(a: str, b: str, limit: int) -> int:
    """Edit distance with adjacent transpositions (optimal string alignment); stops early above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _budget(n: int) -> int:
    """Typos allowed for a key of n letters: none below 5 (Jan, Anna, Nowak are too close to ordinary words)."""
    return 0 if n < 5 else 1 if n < 9 else 2


def close(token_key: str, part_key: str, inflect: int = 0) -> bool:
    """The token is the name part, maybe with typos, maybe with up to `inflect` letters of a case ending."""
    if not part_key or len(token_key) < 3:
        return False
    b = _budget(len(part_key))
    if token_key != part_key and token_key.startswith(part_key):
        # the word plus an ending ('Desktops', 'Users'): an inflection, not a typo; only where endings are allowed
        return inflect > 0 and len(part_key) >= 5 and len(token_key) - len(part_key) <= inflect
    if osa(token_key, part_key, b) <= b:
        return True
    return inflect > 0 and len(part_key) >= 5 and len(token_key) > len(part_key) and len(token_key) - len(part_key) <= inflect and \
        osa(token_key[:len(part_key)], part_key, b) <= b


# words of a text: camelCase split, digits inside a word read as letters (Mu11er) only when the word has letters
_WORD = re.compile(r"[A-Za-z0-9$]+")
_CAMEL = re.compile(r"[A-Z]?[a-z0-9$]+|[A-Z0-9$]+(?![a-z])")


def words(text: str) -> list[tuple[str, str]]:
    """(original word, sound key) for every word of the text."""
    out = []
    for run in _WORD.findall(clean(text)):
        for w in _CAMEL.findall(run) or [run]:
            letters = sum(c.isalpha() for c in w)
            if letters < 2:
                continue
            if letters < len(w):
                if letters < 3:
                    continue
                w2 = w.translate(_LEET)
            else:
                w2 = w
            out.append((w, key(w2)))
    return out


EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}")


def _email_key(e: str) -> str:
    local, _, domain = clean(e).lower().partition("@")
    return re.sub(r"[._+-]", "", local.split("+", 1)[0]) + "@" + domain


def fuzzy_hits(text: str, emails: list[str], names: list[str], first_alone: bool = False,
               extra: list[str] = (), guessed: list[str] = ()) -> list[tuple[str, str]]:
    """(kind, matched text) for look-alike forms of the identity that the exact scanner does not catch."""
    out: list[tuple[str, str]] = []
    ws = words(text)
    for x in extra:
        # any protected phrase (nickname, street, company): every word close, in order; short words exact
        xk = [k for _, k in words(x)]
        if not xk or sum(len(k) for k in xk) < 5:
            continue
        for i in range(len(ws) - len(xk) + 1):
            if all(close(ws[i + j][1], xk[j]) for j in range(len(xk))):
                out.append(("extra-fuzzy", " ".join(w for w, _ in ws[i:i + len(xk)])))
                break
    for n in list(names) + list(guessed):
        parts = [p for p in re.split(r"\s+", n.strip()) if p]
        if len(parts) < 2:
            continue
        fk, lk = key(parts[0]), key(parts[-1])
        for i, (w, k) in enumerate(ws):
            nxt = ws[i + 1][1] if i + 1 < len(ws) else ""
            if (close(k, fk, 3) and close(nxt, lk, 4)) or (close(k, lk, 4) and close(nxt, fk, 3)):
                out.append(("name-fuzzy", f"{w} {ws[i + 1][0]}"))
                break
        else:
            if n not in names:
                continue  # a guessed name (from a first.last@ address) counts only as the full name
            for i, (w, k) in enumerate(ws):
                if len(lk) >= 5 and close(k, lk, 4):
                    prev = ws[i - 1][0] if i else ""
                    # 'Anna Miller' is someone else; the user's own first name (or a typo of it) before it is not
                    if prev[:1].isupper() and prev[1:].islower() and len(prev) >= 3 and not close(key(prev), fk, 3):
                        continue
                    out.append(("surname-fuzzy", w))
                    break
                if first_alone and len(fk) >= 6 and close(k, fk, 3):
                    out.append(("first-fuzzy", w))
                    break
    mine = {_email_key(e) for e in emails if "@" in e}
    if mine:
        cleaned = clean(text)
        for found in EMAIL.findall(cleaned):
            fk_ = _email_key(found)
            if fk_ in mine:
                if found not in text:  # exact only after look-alikes were replaced: 'jаn@x.pl' with a Cyrillic а
                    out.append(("email-fuzzy", found))
                continue
            fl, fd = fk_.split("@", 1)
            for m in mine:
                ml, md = m.split("@", 1)
                b = _budget(len(ml))
                if (fl == ml and osa(fd, md, 1) <= 1) or (fd == md and osa(fl, ml, b) <= b):
                    out.append(("email-fuzzy", found))
                    break
    return out


# fields whose job is to identify the caller
_FIELD = re.compile(
    r"""(?:(?<!\S)(?:-A|--user-agent)(?:\s+|=)(?:"([^"]*)"|'([^']*)'|(\S+)))"""
    r"""|(?:\b(?:user[-_]agent|from|x-contact|x-email|contact)["']?\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s"',}]+)))"""
    r"""|(?:\buser\.email\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+)))"""
    r"""|(?:[?&](?:e-?mail|mail|contact|from)=([^&\s"']+))""",
    re.IGNORECASE)
_PLACEHOLDER = re.compile(r"(?i)@(?:[\w-]+\.)*(?:example\.(?:com|org|net)|example|invalid|test|localhost)$|noreply")


def contact_hits(text: str, alias: list[str]) -> list[tuple[str, str]]:
    """E-mail addresses (anyone's) in User-Agent, From, contact headers, git user.email or e-mail URL parameters."""
    allowed = {_email_key(a) for a in alias if "@" in a}
    out = []
    for m in _FIELD.finditer(text):
        val = unquote_plus(next((g for g in m.groups() if g is not None), ""))
        for e in EMAIL.findall(clean(val)):
            if _email_key(e) in allowed or _PLACEHOLDER.search(e):
                continue
            out.append(("contact-email", e))
    return out
