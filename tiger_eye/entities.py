"""Canonicalisation for threat actors and malware families.

The LLM extraction step writes raw strings like 'Vidar', 'Vidar Stealer',
'vidar stealer' as separate entries — even though they all refer to the
same entity. Aggregation across them is impossible without a normalisation
layer.

This module gives every raw mention a canonical identity:

    canonicalise_malware('Vidar Stealer')   -> ('Vidar',       'vidar')
    canonicalise_malware('vidar')           -> ('Vidar',       'vidar')
    canonicalise_malware('Infostealer')     -> (None,          None)         # generic, filtered
    canonicalise_actor('Attacker')          -> (None,          None)         # generic, filtered
    canonicalise_actor('TeamPCP')           -> ('TeamPCP',     'teampcp')

Algorithm:
  1. Strip + collapse internal whitespace
  2. If the value matches a generic-label regex (Attacker / unknown / etc.)
     return (None, None) — *do not* create an entity for these
  3. Compute the normalised key (lowercase, whitespace-collapsed)
  4. Look up the key in the curated ALIASES map. If found, return its
     canonical name + the key as found.
  5. Otherwise, fall back to the trimmed original as the canonical name.
     A new entity is created on first sight (single-mention novelties).

The maps below are *curated*, not generated. The goal is to collapse the
known noisy cases that appeared in production data, not to attempt fuzzy
matching (which is more likely to introduce bad merges than fix dedup).
Add to the maps as new aliases surface.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Generic-label filters
# ---------------------------------------------------------------------------
# These show up in LLM output as descriptive labels rather than named
# entities. Storing them would pollute leaderboards and confuse joins.

# Vendor / security-research orgs whose names sometimes get hallucinated
# into the actor list. They appear in articles as the *reporters* or
# *product owners*, not the attackers — but the LLM occasionally puts
# them in potential_threat_actors. Filter at canonicalisation.
_VENDOR_DENYLIST: set[str] = {
    # Security tooling / EDR / consultancies
    "anthropic",
    "openai",
    "microsoft",
    "google",
    "cisco",
    "amazon",
    "palo alto networks",
    "palo alto networks researchers",
    "mandiant",
    "crowdstrike",
    "sentinelone",
    "recorded future",
    "qualys",
    "tenable",
    "rapid7",
    "checkmarx",
    "snyk",
    "unit 42",
    "unit42",
    "talos",
    "cisco talos",
    "cisco talos blog",
    "eset",
    "kaspersky",
    "mcafee",
    "trend micro",
    "bitdefender",
    "fortinet",
    "sonicwall",
    "f5",
    "akamai",
    "cloudflare",
    "checkpoint",
    "check point",
    "researchers",
    "security researchers",
    "threat researchers",
    "academic researchers",
    # Research / OEM / spyware that show up tagged-as-actor but aren't ops groups
    "google project zero",
    "project zero",
    "jfrog",
    "jfrog security research",
    "qualys threat research unit",
    "qualys threat research unit (tru)",
    "qualys tru",
    "cloud security alliance",
    "cloud security alliance (csa)",
    "csa",
    "apple",
    "ibm",
    "ibm x-force",
    "x-force",
    "nccgroup",
    "ncc group",
    "blackberry",
    "blackberry research",
    "huntress",
    "huntress labs",
    "wiz",
    "wiz research",
    "trustwave",
    "secureworks",
    "intel471",
    "intel 471",
    "dragos",
    "claroty",
    "armis",
    "checkmarx labs",
    # Law enforcement / regulators / governments (sources, not attackers)
    "fbi",
    "cisa",
    "nsa",
    "europol",
    "interpol",
    "ncsc",
    "ncsc-uk",
    "german authorities",
    "us authorities",
    "uk authorities",
    "french authorities",
    "dutch authorities",
    "chinese authorities",
    # Open-source project / community names / forums (places, not actors)
    "github",
    "gitlab",
    "npm",
    "pypi",
    "breachforums",
    "raidforums",
    "xss.is",
    "exploit.in",
}

# Individual researchers / journalists / engineers that the LLM has placed
# into potential_threat_actors. These are humans, not threat actors. Curate
# observed examples; expand as more leak through. (A future "type=person"
# category on threat_actors would be the right structural fix.)
_INDIVIDUAL_DENYLIST: set[str] = {
    "jann horn",
    "angelo martino",
    "tavis ormandy",
    "brian krebs",
    "matt suiche",
    "mark russinovich",
    "kevin beaumont",
    "dan goodin",
    "lawrence abrams",
    "bill toulas",
    "ionut ilascu",
    "sergiu gatlan",
    "ravie lakshmanan",
    "pierluigi paganini",
    "graham cluley",
    "cambodian senator",  # appeared as victim/named individual
}

# Malware family names that the LLM occasionally puts into the actor
# field as a placeholder when the real operator is unknown. Filter from
# actors. NOTE: We deliberately keep dual-use names (REvil, BlackCat,
# LockBit, ALPHV) as legitimate actor candidates — those names refer
# to operator groups too, not just the malware they ship.
_MALWARE_NOT_ACTORS: set[str] = {
    "mirai",
    "aisuru",  # Mirai-based IoT botnet (2025) — malware, not actor
    "glassworm",
    "filemanager",
    "maverick",
    "sorvepotel",
    "tclbanker",
    "tclbanker.",
    "etherrat",
    "tuktuk",
    "vidar",
    "vidar stealer",
    "lumma",
    "lummac2",
    "lumma stealer",
    "redline",
    "raccoon stealer",
    "stealc",
    "shai-hulud",
    "mini shai-hulud",
    "pcpjack",
    "cloudz",
    "kimwolf",
    "lucidrook",
    "deepload",
    "canisterworm",
    "abcdoor",
    "birdcall",
    "squiddoor",
    "snowrust",
    "snowlight",
    "netdraft",
    "finaldraft",
    "vshell",
    "cloudsorcerer",
    "pamdoora",
    "valleyrat",
    "quasar rat",
    "trickmo",
    "vect 2.0",
    "vect2.0",
}


_GENERIC_ACTOR_PATTERNS = re.compile(
    r"""^(
            attackers?                                  # attacker, attackers
          | (local | remote | external | internal | nearby
             | unauthenticated | authenticated | low[\s-]privilege
            ) \s+ attackers?
          | unknown( \s+ (attackers? | threat \s+ actors?) )?
          | threat \s+ actors?
          | malicious \s+ (cyber \s+)? actors?
          | unauthenticated( \s+ \w+)? \s+ attackers?
          | authenticated( \s+ \w+)? \s+ (user|attackers?)
          | low \s+ privilege \s+ \w+ \s+ user
          | (\w+ \s+ )* attacker \s+ with \s+ .*       # 'attacker with access to...'
          | phishers?
          | scammers?
          | fraudsters?
          | hackers?
          | cybercriminals?
          | criminals?
          | suspected \s+ state-sponsored \s+ hackers?
          | nation-state \s+ actors?
          | state-sponsored \s+ actors?
          | apt \s+ group                              # 'APT group' generic
          | bad \s+ actors?                            # 'bad actor', 'bad actors'
          | dprk                                       # country abbreviation
          | (north \s+ korean | russian | chinese | iranian | belarusian)
            \s+ .* workers?                             # '… IT workers', '(IT) workers' etc.
          # Generic country-attribution descriptors that aren't named actors:
          | (north \s+ korean | russian | chinese | iranian | belarusian
             | israeli | indian | pakistani | turkish | brazilian
             | ukrainian | korean | japanese | vietnamese | dprk)
            \s+ (hackers? | threat \s+ actors? | cyber \s+ actors? | actors?
                 | state \s+ actors? | apt s? | apt \s+ groups? | operators?
                 | cybercriminals? | nationals? | developers? | spies?
                 | nationals?)
          # "China-linked Y", "DPRK-nexus Y", "Iranian-linked hackers" etc.
          | (north[\s-]korean | dprk | russian | chinese | iranian | belarusian
             | israeli | indian | pakistani | korean | japanese | vietnamese
             | china | russia | iran | north[\s-]korea | israel | india
             | pakistan | brazil | ukraine | turkey)
            [\s-]
            (linked | nexus | aligned | backed | sponsored | based | affiliated)
            \s+ (hackers? | threat \s+ actors? | cyber \s+ actors? | actors?
                 | state \s+ actors? | apt s? | apt \s+ groups? | operators?
                 | cybercriminals? | hacker \s+ groups?)
          | criminal \s+ (organizations? | organisations? | groups?)
          | china \s+ apt                              # 'China APT' is too generic alone
          | china                                      # bare country names
          | russia
          | iran
          | north \s+ korea
          | israel
          | unidentified \s+ \w+
       )$""",
    re.IGNORECASE | re.VERBOSE,
)

# Generic malware-category labels that aren't named families.
_GENERIC_MALWARE_PATTERNS = re.compile(
    r"""^(
            (banking \s+)? trojans?                    # 'banking trojans', 'trojan'
          | malware
          | ransomware
          | infostealer
          | info-stealer
          | infostealers
          | credential \s+ stealer
          | mobile \s+ malware
          | (rat | remote \s+ access \s+ trojan ) s?
          | spyware
          | adware
          | rootkit
          | botnet
          | worm
          | wiper
          | loader
          | dropper
          | downloader
          | backdoor
          | python-based \s+ .*
          | generic[_\s-]\w+                           # generic_infostealer etc.
          | unknown( \s+ malware )?
       )$""",
    re.IGNORECASE | re.VERBOSE,
)


def _norm_key(s: str) -> str:
    """Normalisation key: lowercase, strip, collapse internal whitespace."""
    return re.sub(r"\s+", " ", s.strip().lower())


# ---------------------------------------------------------------------------
# Curated alias maps — normalised key  ->  canonical_name
# ---------------------------------------------------------------------------
# Add an entry every time you see two variants of the same entity show up
# as separate rows in the entity table after deploy.

_MALWARE_ALIASES: dict[str, str] = {
    # ===== Infostealers =====
    "vidar": "Vidar",
    "vidar stealer": "Vidar",
    "lumma": "LummaC2",
    "lummac2": "LummaC2",
    "lumma stealer": "LummaC2",
    "lummac2 stealer": "LummaC2",
    "stealc": "Stealc",
    "redline": "RedLine",
    "redline stealer": "RedLine",
    "raccoon": "Raccoon Stealer",
    "raccoon stealer": "Raccoon Stealer",
    # ===== Supply-chain worms =====
    "shai-hulud": "Shai-Hulud",
    "shai hulud": "Shai-Hulud",
    "mini shai-hulud": "Mini Shai-Hulud",
    "mini shai hulud": "Mini Shai-Hulud",
    # ===== Ransomware (canonical name preserves family casing) =====
    "lockbit": "LockBit",
    "lockbit3.0": "LockBit",
    "lockbit 3.0": "LockBit",
    "lockbit3": "LockBit",
    "lockbit black": "LockBit",
    "blackcat": "ALPHV/BlackCat",
    "alphv": "ALPHV/BlackCat",
    "alphv/blackcat": "ALPHV/BlackCat",
    "alphv blackcat": "ALPHV/BlackCat",
    "revil": "REvil",
    "sodinokibi": "REvil",
    "medusa": "Medusa",
    "medusa ransomware": "Medusa",
    "chaos": "Chaos",
    "chaos ransomware": "Chaos",
    "qilin": "Qilin",
    "agenda": "Qilin",
    "ransomhub": "RansomHub",
    "ransomhouse": "RansomHouse",
    "karakurt": "Karakurt",
    "gandcrab": "GandCrab",
    "sorry": "Sorry",
    "sorry ransomware": "Sorry",
    # ===== Banking trojans =====
    "trickmo": "TrickMo",
    "tclbanker": "TCLBANKER",
    "tclbanker.": "TCLBANKER",
    "tcl banker": "TCLBANKER",
    "tclbanker banking trojan": "TCLBANKER",
    # ===== RATs / backdoors =====
    "quasar": "Quasar RAT",
    "quasar rat": "Quasar RAT",
    "quasarrat": "Quasar RAT",
    "quasar linux rat": "Quasar RAT",  # variant note: linux build
    "valleyrat": "ValleyRAT",
    "etherrat": "EtherRAT",
    "pamdoora": "PamDOORa",
    "abcdoor": "ABCDoor",
    "birdcall": "BirdCall",
    "squiddoor": "SquidDoor",
    "snowrust": "SNOWRUST",
    "snowlight": "SNOWLIGHT",
    "netdraft": "NetDraft",
    "finaldraft": "FinalDraft",
    "vshell": "VSHELL",
    "cloudsorcerer": "CloudSorcerer",
    "filemanager": "Filemanager",
    "zichatbot": "ZiChatBot",
    # ===== Worms / botnets =====
    "mirai": "Mirai",
    "glassworm": "GlassWorm",
    "canisterworm": "CanisterWorm",
    # ===== Wipers =====
    "lotus wiper": "Lotus Wiper",
    # ===== Other from production data =====
    "cloudz": "CloudZ",
    "pcpjack": "PCPJack",
    "pheno": "Pheno",
    "qlnx": "QLNX",
    "kimwolf": "Kimwolf",
    "lucidrook": "LucidRook",
    "deepload": "DeepLoad",
    "zionsiphon": "ZionSiphon",
    "vect 2.0": "Vect 2.0",
    "vect2.0": "Vect 2.0",
    "vect 2": "Vect 2.0",
    "tcktck": "TukTuk",
    "tuktuk": "TukTuk",
    "crpx0": "CRPx0",
    "maverick": "Maverick",
    "sorvepotel": "SORVEPOTEL",
    "fast16": "fast16",
    "snow": "Snow",
    "xlabs_v1": "xlabs_v1",
    "xlabs v1": "xlabs_v1",
}

# Default category hint per canonical name — surfaces in the entity row
# at creation time. Updatable later by hand.
_MALWARE_CATEGORY: dict[str, str] = {
    # infostealers
    "Vidar": "infostealer",
    "LummaC2": "infostealer",
    "Stealc": "infostealer",
    "RedLine": "infostealer",
    "Raccoon Stealer": "infostealer",
    # ransomware
    "LockBit": "ransomware",
    "ALPHV/BlackCat": "ransomware",
    "REvil": "ransomware",
    "Medusa": "ransomware",
    "Chaos": "ransomware",
    "Qilin": "ransomware",
    "RansomHub": "ransomware",
    "RansomHouse": "ransomware",
    "Karakurt": "ransomware",
    "GandCrab": "ransomware",
    "Sorry": "ransomware",
    # banking trojans
    "TrickMo": "banking-trojan",
    "TCLBANKER": "banking-trojan",
    # RATs / backdoors
    "Quasar RAT": "rat",
    "ValleyRAT": "rat",
    "EtherRAT": "rat",
    "PamDOORa": "backdoor",
    "ABCDoor": "backdoor",
    "BirdCall": "backdoor",
    "SquidDoor": "backdoor",
    "NetDraft": "backdoor",
    "FinalDraft": "backdoor",
    "VSHELL": "backdoor",
    "CloudSorcerer": "backdoor",
    "Filemanager": "backdoor",
    "SNOWRUST": "backdoor",
    "SNOWLIGHT": "backdoor",
    # worms / botnets
    "Mirai": "botnet",
    "GlassWorm": "worm",
    "CanisterWorm": "worm",
    "Shai-Hulud": "worm",
    "Mini Shai-Hulud": "worm",
    # wipers
    "Lotus Wiper": "wiper",
}

# ---------------------------------------------------------------------------
# Threat actor aliases
# ---------------------------------------------------------------------------

_ACTOR_ALIASES: dict[str, str] = {
    # ===== Active in our corpus =====
    "teampcp": "TeamPCP",
    "shinyhunters": "ShinyHunters",
    "shinyhunter": "ShinyHunters",
    "shiny hunters": "ShinyHunters",
    "mr_rot13": "Mr_Rot13",
    # ===== Well-known APTs (pre-seed so first mention canonicalises) =====
    # Russia
    "apt28": "APT28",
    "fancy bear": "APT28",
    "strontium": "APT28",
    "forest blizzard": "APT28",
    "fancybear": "APT28",
    "apt29": "APT29",
    "cozy bear": "APT29",
    "nobelium": "APT29",
    "midnight blizzard": "APT29",
    "the dukes": "APT29",
    "sandworm": "Sandworm",
    "voodoo bear": "Sandworm",
    "seashell blizzard": "Sandworm",
    "iridium": "Sandworm",
    # China
    "apt41": "APT41",
    "winnti": "APT41",
    "wicked panda": "APT41",
    "barium": "APT41",
    "volt typhoon": "Volt Typhoon",
    "bronze silhouette": "Volt Typhoon",
    "vanguard panda": "Volt Typhoon",
    "mustang panda": "Mustang Panda",
    "ta416": "Mustang Panda",
    "reddelta": "Mustang Panda",
    "salt typhoon": "Salt Typhoon",
    "flax typhoon": "Flax Typhoon",
    "ethereal panda": "Flax Typhoon",
    # North Korea
    "lazarus": "Lazarus Group",
    "lazarus group": "Lazarus Group",
    "hidden cobra": "Lazarus Group",
    "apt38": "Lazarus Group",
    "kimsuky": "Kimsuky",
    "velvet chollima": "Kimsuky",
    "thallium": "Kimsuky",
    "black banshee": "Kimsuky",
    # Iran
    "apt33": "APT33",
    "elfin": "APT33",
    "refined kitten": "APT33",
    "apt34": "APT34",
    "oilrig": "APT34",
    # eCrime / financial
    "fin7": "FIN7",
    "carbon spider": "FIN7",
    "itg14": "FIN7",
    "scattered spider": "Scattered Spider",
    "unc3944": "Scattered Spider",
    "octo tempest": "Scattered Spider",
    "muddled libra": "Scattered Spider",
    "uat-8302": "UAT-8302",
    "uat8302": "UAT-8302",
    # ===== Additional well-known APTs / threat groups =====
    # Russia
    "apt28 (gru)": "APT28",
    "gru": "APT28",  # the GRU operates APT28; collapse for analytical leaderboards
    "bluedelta": "APT28",
    "snake": "Turla",
    "turla": "Turla",
    "venomous bear": "Turla",
    # China — expanded
    "famoussparrow": "FamousSparrow",
    "famous sparrow": "FamousSparrow",
    "silk typhoon": "Silk Typhoon",
    "hafnium": "Silk Typhoon",
    "earth lamia": "Earth Lamia",
    "uat-10608": "UAT-10608",
    # North Korea — expanded
    "apt37": "APT37",
    "inkysquid": "APT37",
    "reaper": "APT37",
    "scarcruft": "ScarCruft",
    "contagious interview": "Contagious Interview",
    # Iran — expanded
    "muddywater": "MuddyWater",
    "mercury": "MuddyWater",
    "static kitten": "MuddyWater",
    "handala": "Handala",
    "handala hack team": "Handala",
    "handala hack": "Handala",
    # eCrime / ransomware affiliates — now have categories below
    "lapsus$": "LAPSUS$",
    "lapsus": "LAPSUS$",
    "revil": "REvil",
    "sodinokibi": "REvil",
    "blackcat": "BlackCat",
    "blackcat (alphv)": "BlackCat",
    "alphv": "BlackCat",
    "gandcrab": "GandCrab",
    "qilin": "Qilin",
    "agenda": "Qilin",
    "ransomhub": "RansomHub",
    "interlock": "Interlock",
    "interlock ransomware group": "Interlock",
    "storm-1175": "Storm-1175",
    # Mandiant / Microsoft tracked clusters
    "unc6692": "UNC6692",
    # Commercial surveillance / mercenary-spyware
    "intellexa": "Intellexa",
    "nso group": "NSO Group",
    "nso": "NSO Group",
    "candiru": "Candiru",
}

_ACTOR_CATEGORY: dict[str, str] = {
    # state-sponsored — Russia
    "APT28": "state-sponsored",
    "APT29": "state-sponsored",
    "Sandworm": "state-sponsored",
    "Turla": "state-sponsored",
    # state-sponsored — China
    "APT41": "state-sponsored",
    "Volt Typhoon": "state-sponsored",
    "Mustang Panda": "state-sponsored",
    "Salt Typhoon": "state-sponsored",
    "Flax Typhoon": "state-sponsored",
    "UAT-8302": "state-sponsored",
    "FamousSparrow": "state-sponsored",
    "Silk Typhoon": "state-sponsored",
    "Earth Lamia": "state-sponsored",
    "UAT-10608": "state-sponsored",
    # state-sponsored — North Korea
    "Lazarus Group": "state-sponsored",
    "Kimsuky": "state-sponsored",
    "APT37": "state-sponsored",
    "ScarCruft": "state-sponsored",
    "Contagious Interview": "state-sponsored",
    # state-sponsored — Iran
    "APT33": "state-sponsored",
    "APT34": "state-sponsored",
    "MuddyWater": "state-sponsored",
    # Mandiant / vendor-tracked clusters (unattributed but operator-class)
    "UNC6692": "state-sponsored",
    # hacktivist
    "Handala": "hacktivist",
    # commercial spyware vendors (mercenary surveillance, not state-aligned ops groups)
    "Intellexa": "commercial-spyware",
    "NSO Group": "commercial-spyware",
    "Candiru": "commercial-spyware",
    # eCrime / ransomware affiliates
    "ShinyHunters": "cybercrime",
    "FIN7": "cybercrime",
    "Scattered Spider": "cybercrime",
    "TeamPCP": "cybercrime",
    "LAPSUS$": "cybercrime",
    "REvil": "cybercrime",
    "BlackCat": "cybercrime",
    "GandCrab": "cybercrime",
    "Qilin": "cybercrime",
    "RansomHub": "cybercrime",
    "Interlock": "cybercrime",
    "Storm-1175": "cybercrime",
}

_ACTOR_COUNTRY: dict[str, str] = {
    # Russia
    "APT28": "RU",
    "APT29": "RU",
    "Sandworm": "RU",
    "Turla": "RU",
    # China
    "APT41": "CN",
    "Volt Typhoon": "CN",
    "Mustang Panda": "CN",
    "Salt Typhoon": "CN",
    "Flax Typhoon": "CN",
    "UAT-8302": "CN",
    "FamousSparrow": "CN",
    "Silk Typhoon": "CN",
    "Earth Lamia": "CN",
    "UAT-10608": "CN",
    # North Korea
    "Lazarus Group": "KP",
    "Kimsuky": "KP",
    "APT37": "KP",
    "ScarCruft": "KP",
    "Contagious Interview": "KP",
    # Iran
    "APT33": "IR",
    "APT34": "IR",
    "MuddyWater": "IR",
    "Handala": "IR",
    # Commercial spyware vendors (vendor HQ country)
    "Intellexa": "GR",  # Greece-based group (also Israeli ties)
    "NSO Group": "IL",
    "Candiru": "IL",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

CanonResult = tuple[str | None, str | None]


def canonicalise_malware(raw: str | None) -> CanonResult:
    """Return (canonical_name, normalised_key) for a malware mention.

    Returns (None, None) for generic-category labels we deliberately don't
    store as named families (ransomware, infostealer, banking trojans, …).
    """
    if not raw or not isinstance(raw, str):
        return (None, None)
    trimmed = re.sub(r"\s+", " ", raw.strip())
    if not trimmed:
        return (None, None)
    if _GENERIC_MALWARE_PATTERNS.match(trimmed):
        return (None, None)
    key = _norm_key(trimmed)
    canonical = _MALWARE_ALIASES.get(key, trimmed)
    return (canonical, _norm_key(canonical))


def canonicalise_actor(raw: str | None) -> CanonResult:
    """Return (canonical_name, normalised_key) for a threat-actor mention.

    Returns (None, None) for:
      * generic-actor labels (Attacker / unknown / suspected state-sponsored …)
      * vendor / research-org names that LLM extraction occasionally
        hallucinates into the actor field (Anthropic, Qualys, Unit 42, …)
      * individual researcher / journalist names that surface as
        potential actors (Jann Horn, Brian Krebs, Tavis Ormandy, …)
      * malware family names mistakenly placed in the actor field
        (Mirai, GlassWorm, Filemanager, …). Dual-use names with both
        a malware family AND a known operator group (REvil, BlackCat,
        LockBit) are NOT filtered — those legitimately appear as actors.
    """
    if not raw or not isinstance(raw, str):
        return (None, None)
    trimmed = re.sub(r"\s+", " ", raw.strip())
    if not trimmed:
        return (None, None)
    if _GENERIC_ACTOR_PATTERNS.match(trimmed):
        return (None, None)
    key = _norm_key(trimmed)
    if key in _VENDOR_DENYLIST or key in _INDIVIDUAL_DENYLIST or key in _MALWARE_NOT_ACTORS:
        return (None, None)
    canonical = _ACTOR_ALIASES.get(key, trimmed)
    return (canonical, _norm_key(canonical))


def malware_category(canonical_name: str) -> str | None:
    return _MALWARE_CATEGORY.get(canonical_name)


def actor_category(canonical_name: str) -> str | None:
    return _ACTOR_CATEGORY.get(canonical_name)


def actor_country(canonical_name: str) -> str | None:
    return _ACTOR_COUNTRY.get(canonical_name)
