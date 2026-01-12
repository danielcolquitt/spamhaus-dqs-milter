#!/usr/bin/env python3
"""
Spamhaus DQS (DBL + ZRD + ZEN) milter for Postfix/Sendmail MTA

- CONNECT: checks connecting IP against ZEN (via DQS)
- HELO/EHLO: checks HELO domain against DBL+ZRD (via DQS)
- MAIL FROM: checks MAIL FROM domain against DBL+ZRD (via DQS)

Policy:
- DBL: reject only 127.0.1.2-99 ("safe to block")  (Spamhaus docs)
- ZRD: reject 127.0.2.2-24 ("domain too young")    (Spamhaus docs)
- ZEN: reject if return code is in SPAMHAUS_DQS_ZEN_REJECT_CODES (default: 2,3,4,9,10,11)
- Treat 127.255.255.* as error codes (fail open)

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.

SPDX-License-Identifier: MPL-2.0

Copyright (c) 2026 Daniel Colquitt
"""

from __future__ import annotations
import os
import re
import time
import ipaddress
import threading
import logging
import logging.handlers
from dataclasses import dataclass
from collections import OrderedDict
from typing import Optional, Tuple, List, FrozenSet

import dns.resolver
import dns.exception
import Milter


# -------------------------
# Defaults (override via env / env file)
# -------------------------
DEFAULT_ENV_FILE = "/etc/spamhaus-dqs-milter.env"

DEFAULT_LISTEN = "inet:11332@localhost"
DEFAULT_MILTER_TIMEOUT = 2  # pymilter expects int seconds

DEFAULT_CACHE_MAX = 20000
DEFAULT_CACHE_TTL_LISTED = 600
DEFAULT_CACHE_TTL_UNLISTED = 300

DEFAULT_DNS_PER_TRY = 0.7
DEFAULT_DNS_LIFETIME = 1.8  # keep < milter_timeout

DEFAULT_NAMESERVERS = "127.0.0.1,::1"  # unbound on localhost
DEFAULT_LOG_LEVEL = "INFO"

# ZEN (IP reputation via DQS)
DEFAULT_ZEN_ENABLE = "1"
DEFAULT_ZEN_REJECT_CODES = "2,3,4,9,10,11"  # SBL, CSS, XBL, DROP/EDROP, PBL

DBL_ZONE = "dbl.dq.spamhaus.net"
ZRD_ZONE = "zrd.dq.spamhaus.net"
ZEN_ZONE = "zen.dq.spamhaus.net"

DEFAULT_IP_WHITELIST = ""  # e.g. "192.0.2.10,2001:db8::1"
DEFAULT_DOMAIN_WHITELIST = ""  # exact domains (applies to both HELO and MAIL FROM)
DEFAULT_DOMAIN_SUFFIX_WHITELIST = ""  # suffixes like "example.com,example.edu"
DEFAULT_WHITELIST_SKIP_ALL = (
    "0"  # if 1 and IP whitelisted -> skip all checks for that connection
)

DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


# -------------------------
# Env file loader
# -------------------------
def load_env_file(path: str) -> None:
    """
    Minimal EnvironmentFile/.env loader.
    Supports:
      KEY=value
      KEY="value"
      # comments
    Does not overwrite variables already set in the environment.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, v = s.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'").strip('"')
                if k and k not in os.environ:
                    os.environ[k] = v
    except FileNotFoundError:
        return


def getenv_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v else default


def getenv_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def getenv_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if not v:
        return default
    try:
        return float(v)
    except ValueError:
        return default


def parse_nameservers(s: str) -> List[str]:
    out: List[str] = []
    for item in (s or "").split(","):
        ns = item.strip()
        if ns:
            out.append(ns)
    return out


def parse_int_set(csv: str) -> FrozenSet[int]:
    out: set[int] = set()
    for part in (csv or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except ValueError:
            continue
    return frozenset(out)


def parse_csv_set(csv: str) -> FrozenSet[str]:
    items = []
    for part in (csv or "").split(","):
        s = part.strip().lower().rstrip(".")
        if s:
            items.append(s)
    return frozenset(items)


def parse_ip_set(csv: str) -> FrozenSet[str]:
    out = []
    for part in (csv or "").split(","):
        s = part.strip()
        if not s:
            continue
        try:
            out.append(str(ipaddress.ip_address(s)))
        except ValueError:
            continue
    return frozenset(out)


def domain_is_whitelisted(
    domain: str, exact: FrozenSet[str], suffixes: FrozenSet[str]
) -> bool:
    d = _norm_domain(domain)
    if not d:
        return False
    if d in exact:
        return True
    for suf in suffixes:
        # allow exact match on suffix too
        if d == suf or d.endswith("." + suf):
            return True
    return False


# -------------------------
# Logging
# -------------------------
logger = logging.getLogger("spamhaus_dqs_milter")
logger.addHandler(logging.NullHandler())


def setup_logging(level_name: str) -> None:
    level_name = (level_name or DEFAULT_LOG_LEVEL).upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)

    syslog = logging.handlers.SysLogHandler(address="/dev/log")
    formatter = logging.Formatter("%(name)s: %(levelname)s: %(message)s")
    syslog.setFormatter(formatter)

    logger.handlers.clear()
    logger.addHandler(syslog)


# -------------------------
# Config
# -------------------------
@dataclass(frozen=True)
class Config:
    api_key: str
    listen: str
    dns_lifetime: float
    dns_per_try: float
    milter_timeout: int
    cache_max: int
    ttl_listed: int
    ttl_unlisted: int
    nameservers: Tuple[str, ...]
    log_level: str
    zen_enable: bool
    zen_reject_codes: Tuple[int, ...]
    zen_reject_set: FrozenSet[int]
    ip_whitelist: FrozenSet[str]
    domain_whitelist: FrozenSet[str]
    domain_suffix_whitelist: FrozenSet[str]
    whitelist_skip_all: bool


# -------------------------
# DNS Resolver
# -------------------------
resolver = dns.resolver.Resolver(configure=False)
resolver.search = []  # never append local search domains


def configure_resolver(
    nameservers: Tuple[str, ...], per_try: float, lifetime: float
) -> None:
    resolver.nameservers = list(nameservers)
    resolver.timeout = max(0.05, per_try)
    resolver.lifetime = max(0.10, lifetime)


def _query_a(qname: str) -> Tuple[str, ...]:
    """
    Resolve A with bounded total time.
    Try UDP, then (if timeout) TCP using remaining lifetime.
    """
    start = time.monotonic()
    try:
        ans = resolver.resolve(qname, "A", tcp=False)
        return tuple(str(r) for r in ans)
    except dns.exception.Timeout:
        elapsed = time.monotonic() - start
        remaining = max(0.2, resolver.lifetime - elapsed)
        ans = resolver.resolve(qname, "A", tcp=True, lifetime=remaining)
        return tuple(str(r) for r in ans)


def _is_spamhaus_error_code(code: str) -> bool:
    return code.startswith("127.255.255.")


def _dbl_should_reject(codes: Tuple[str, ...]) -> bool:
    for c in codes:
        if _is_spamhaus_error_code(c):
            continue
        if c.startswith("127.0.1."):
            try:
                last = int(c.rsplit(".", 1)[1])
            except ValueError:
                continue
            if 2 <= last <= 99:
                return True
    return False


def _zrd_should_reject(codes: Tuple[str, ...]) -> bool:
    for c in codes:
        if _is_spamhaus_error_code(c):
            continue
        if c.startswith("127.0.2."):
            try:
                last = int(c.rsplit(".", 1)[1])
            except ValueError:
                continue
            if 2 <= last <= 24:
                return True
    return False


def _zen_should_reject(codes: Tuple[str, ...], reject_set: FrozenSet[int]) -> bool:
    for c in codes:
        if _is_spamhaus_error_code(c):
            continue
        if c.startswith("127.0.0."):
            try:
                last = int(c.rsplit(".", 1)[1])
            except ValueError:
                continue
            if last in reject_set:
                return True
    return False


# -------------------------
# Cache (LRU + TTL)
# -------------------------
@dataclass(frozen=True)
class DomainCacheValue:
    expires: float
    dbl_codes: Tuple[str, ...]
    zrd_codes: Tuple[str, ...]


@dataclass(frozen=True)
class IpCacheValue:
    expires: float
    zen_codes: Tuple[str, ...]


_domain_cache_lock = threading.Lock()
_domain_cache: "OrderedDict[str, DomainCacheValue]" = OrderedDict()

_ip_cache_lock = threading.Lock()
_ip_cache: "OrderedDict[str, IpCacheValue]" = OrderedDict()


def _now() -> float:
    return time.monotonic()


def _lru_ttl_get(cache: "OrderedDict[str, object]", lock: threading.Lock, key: str):
    with lock:
        cv = cache.get(key)
        if not cv:
            return None
        if cv.expires <= _now():  # type: ignore[attr-defined]
            cache.pop(key, None)
            return None
        cache.move_to_end(key, last=True)
        return cv


def _lru_ttl_put(
    cache: "OrderedDict[str, object]", lock: threading.Lock, key: str, cv, maxsize: int
):
    with lock:
        cache[key] = cv
        cache.move_to_end(key, last=True)
        while len(cache) > maxsize:
            cache.popitem(last=False)


# -------------------------
# Helpers
# -------------------------
def _norm_domain(s: Optional[str]) -> str:
    s = (s or "").strip().lower()
    return s.rstrip(".")


def extract_domain(addr: str) -> Optional[str]:
    if not addr:
        return None
    s = addr.strip().strip("<>").strip()
    if s == "":
        return None
    if "@" in s:
        return s.split("@", 1)[1]
    return s


def _reverse_ip_for_rbl(ip: str) -> Optional[str]:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None

    if not obj.is_global:
        return None

    if obj.version == 4:
        return ".".join(reversed(str(obj).split(".")))

    hexstr = obj.exploded.replace(":", "")
    return ".".join(reversed(hexstr))


# -------------------------
# Domain checks (DBL + ZRD)
# -------------------------
def check_domain(
    dom: str, cfg: Config
) -> Tuple[bool, bool, Tuple[str, ...], Tuple[str, ...]]:
    dom = _norm_domain(dom)
    if not dom or not DOMAIN_RE.match(dom):
        return (False, False, (), ())

    cached = _lru_ttl_get(_domain_cache, _domain_cache_lock, dom)
    if cached:
        dbl_codes, zrd_codes = cached.dbl_codes, cached.zrd_codes
        return (
            _dbl_should_reject(dbl_codes),
            _zrd_should_reject(zrd_codes),
            dbl_codes,
            zrd_codes,
        )

    dbl_q = f"{dom}.{cfg.api_key}.{DBL_ZONE}"
    zrd_q = f"{dom}.{cfg.api_key}.{ZRD_ZONE}"

    dbl_codes: Tuple[str, ...] = ()
    zrd_codes: Tuple[str, ...] = ()

    try:
        dbl_codes = _query_a(dbl_q)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("DBL query ok domain=%s codes=%s", dom, dbl_codes)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        dbl_codes = ()
    except Exception as e:
        logger.warning("DNS failure (DBL) domain=%s err=%s", dom, e)
        dbl_codes = ()

    if any(_is_spamhaus_error_code(c) for c in dbl_codes):
        logger.warning(
            "Spamhaus DBL error return-code(s) domain=%s codes=%s", dom, dbl_codes
        )

    dbl_reject = _dbl_should_reject(dbl_codes)

    if dbl_reject:
        zrd_codes = ()
        zrd_reject = False
    else:
        try:
            zrd_codes = _query_a(zrd_q)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "ZRD query ok domain=%s codes=%s", dom, zrd_codes
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            zrd_codes = ()
        except Exception as e:
            logger.warning("DNS failure (ZRD) domain=%s err=%s", dom, e)
            zrd_codes = ()

        if any(_is_spamhaus_error_code(c) for c in zrd_codes):
            logger.warning(
                "Spamhaus ZRD error return-code(s) domain=%s codes=%s", dom, zrd_codes
            )

        zrd_reject = _zrd_should_reject(zrd_codes)

    ttl = cfg.ttl_listed if (dbl_reject or zrd_reject) else cfg.ttl_unlisted
    _lru_ttl_put(
        _domain_cache,
        _domain_cache_lock,
        dom,
        DomainCacheValue(
            expires=_now() + ttl, dbl_codes=dbl_codes, zrd_codes=zrd_codes
        ),
        cfg.cache_max,
    )
    return (dbl_reject, zrd_reject, dbl_codes, zrd_codes)


# -------------------------
# IP checks (ZEN)
# -------------------------
def check_ip_zen(ip: str, cfg: Config) -> Tuple[bool, Tuple[str, ...]]:
    rev = _reverse_ip_for_rbl(ip)
    if not rev:
        return (False, ())

    key = f"ip:{ip}"
    cached = _lru_ttl_get(_ip_cache, _ip_cache_lock, key)
    if cached:
        zen_codes = cached.zen_codes
        return (_zen_should_reject(zen_codes, cfg.zen_reject_set), zen_codes)

    q = f"{rev}.{cfg.api_key}.{ZEN_ZONE}"

    try:
        zen_codes = _query_a(q)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("ZEN query ok ip=%s codes=%s", ip, zen_codes)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        zen_codes = ()
    except Exception as e:
        logger.warning("DNS failure (ZEN) ip=%s err=%s", ip, e)
        zen_codes = ()

    if any(_is_spamhaus_error_code(c) for c in zen_codes):
        logger.warning(
            "Spamhaus ZEN error return-code(s) ip=%s codes=%s", ip, zen_codes
        )

    zen_reject = _zen_should_reject(zen_codes, cfg.zen_reject_set)

    ttl = cfg.ttl_listed if zen_reject else cfg.ttl_unlisted
    _lru_ttl_put(
        _ip_cache,
        _ip_cache_lock,
        key,
        IpCacheValue(expires=_now() + ttl, zen_codes=zen_codes),
        cfg.cache_max,
    )
    return (zen_reject, zen_codes)


# -------------------------
# Milter
# -------------------------
class SpamhausDQSMilter(Milter.Base):
    cfg: Config = None  # set in main()

    def __init__(self):
        super().__init__()
        self.peer = None
        self._skip_all = False

    def connect(self, hostname, family, hostaddr):
        self.peer = (hostname, hostaddr)
        logger.debug("CONNECT hostname=%r hostaddr=%r", hostname, hostaddr)

        ip = None
        if isinstance(hostaddr, tuple) and len(hostaddr) >= 1:
            ip = hostaddr[0]
        elif isinstance(hostaddr, str):
            ip = hostaddr

        ip_norm: Optional[str] = None
        if ip:
            try:
                ip_norm = str(ipaddress.ip_address(str(ip)))
            except ValueError:
                ip_norm = None

        # IP whitelist (optionally skip all checks for this connection)
        if ip_norm and ip_norm in self.cfg.ip_whitelist:
            logger.info(
                "WHITELIST CONNECT ip=%s (skipping ZEN%s)",
                ip_norm,
                " + all checks" if self.cfg.whitelist_skip_all else "",
            )
            if self.cfg.whitelist_skip_all:
                self._skip_all = True
            return Milter.CONTINUE

        # ZEN check at CONNECT
        if self.cfg.zen_enable and ip_norm:
            zen_reject, zen_codes = check_ip_zen(ip_norm, self.cfg)
            if zen_reject:
                logger.info("REJECT CONNECT: ZEN ip=%s codes=%s", ip_norm, zen_codes)
                self.setreply(
                    "554",
                    "5.7.1",
                    "Connecting IP address is rejected due to a security policy violation.",
                )
                return Milter.REJECT

        return Milter.CONTINUE

    def helo(self, heloname):
        return self.hello(heloname)

    def hello(self, heloname):
        if getattr(self, "_skip_all", False):
            return Milter.CONTINUE

        raw = heloname or ""
        helo_dom = _norm_domain(raw)
        logger.debug("HELO/EHLO seen raw=%r domain=%r", raw, helo_dom)

        if domain_is_whitelisted(
            helo_dom, self.cfg.domain_whitelist, self.cfg.domain_suffix_whitelist
        ):
            logger.info("WHITELIST HELO domain=%s (skipping DBL/ZRD)", helo_dom)
            return Milter.CONTINUE
        elif helo_dom.startswith("[") and helo_dom.endswith("]"):
            return Milter.CONTINUE

        dbl_reject, zrd_reject, dbl_codes, zrd_codes = check_domain(helo_dom, self.cfg)

        if zrd_reject:
            logger.info("REJECT HELO: ZRD domain=%s codes=%s", helo_dom, zrd_codes)
            self.setreply(
                "550",
                "5.7.1",
                "Policy rejection: HELO domain has no established reputation.",
            )
            return Milter.REJECT

        if dbl_reject:
            logger.info("REJECT HELO: DBL domain=%s codes=%s", helo_dom, dbl_codes)
            self.setreply(
                "550",
                "5.7.1",
                "HELO domain is rejected due to a security policy violation.",
            )
            return Milter.REJECT

        return Milter.CONTINUE

    def envfrom(self, mailfrom, *args):
        if getattr(self, "_skip_all", False):
            return Milter.CONTINUE

        raw = mailfrom or ""
        dom = _norm_domain(extract_domain(raw))
        logger.debug("MAIL FROM seen raw=%r domain=%r", raw, dom)

        if domain_is_whitelisted(
            dom, self.cfg.domain_whitelist, self.cfg.domain_suffix_whitelist
        ):
            logger.info("WHITELIST MAILFROM domain=%s (skipping DBL/ZRD)", dom)
            return Milter.CONTINUE

        dbl_reject, zrd_reject, dbl_codes, zrd_codes = check_domain(dom, self.cfg)

        if zrd_reject:
            logger.info("REJECT MAILFROM: ZRD domain=%s codes=%s", dom, zrd_codes)
            self.setreply(
                "550",
                "5.7.1",
                "Policy rejection: sender domain has no established reputation.",
            )
            return Milter.REJECT

        if dbl_reject:
            logger.info("REJECT MAILFROM: DBL domain=%s codes=%s", dom, dbl_codes)
            self.setreply(
                "550",
                "5.7.1",
                "Sender domain is rejected due to a security policy violation.",
            )
            return Milter.REJECT

        return Milter.CONTINUE

    def eom(self):
        return Milter.ACCEPT


def main() -> None:
    env_path = getenv_str("SPAMHAUS_DQS_ENV_FILE", DEFAULT_ENV_FILE)
    load_env_file(env_path)

    log_level = getenv_str("SPAMHAUS_DQS_LOG_LEVEL", DEFAULT_LOG_LEVEL)
    setup_logging(log_level)

    api_key = os.getenv("SPAMHAUS_DQS_API_KEY")
    if not api_key:
        logger.error(
            "Missing SPAMHAUS_DQS_API_KEY (set it in %s or environment)", env_path
        )
        raise SystemExit(2)

    listen = getenv_str("SPAMHAUS_DQS_LISTEN", DEFAULT_LISTEN)

    dns_per_try = getenv_float("SPAMHAUS_DQS_DNS_PER_TRY", DEFAULT_DNS_PER_TRY)
    dns_lifetime = getenv_float("SPAMHAUS_DQS_DNS_LIFETIME", DEFAULT_DNS_LIFETIME)
    milter_timeout = getenv_int("SPAMHAUS_DQS_MILTER_TIMEOUT", DEFAULT_MILTER_TIMEOUT)

    # Ensure lifetime < milter timeout (leave headroom)
    dns_lifetime = min(dns_lifetime, max(0.5, milter_timeout - 0.1))
    # Ensure per-try leaves some lifetime for fallback
    dns_per_try = min(dns_per_try, max(0.2, dns_lifetime - 0.1))

    cache_max = getenv_int("SPAMHAUS_DQS_CACHE_MAX", DEFAULT_CACHE_MAX)
    ttl_listed = getenv_int("SPAMHAUS_DQS_CACHE_TTL_LISTED", DEFAULT_CACHE_TTL_LISTED)
    ttl_unlisted = getenv_int(
        "SPAMHAUS_DQS_CACHE_TTL_UNLISTED", DEFAULT_CACHE_TTL_UNLISTED
    )

    nameservers = tuple(
        parse_nameservers(getenv_str("SPAMHAUS_DQS_NAMESERVERS", DEFAULT_NAMESERVERS))
    ) or tuple(parse_nameservers(DEFAULT_NAMESERVERS))

    zen_enable = getenv_str(
        "SPAMHAUS_DQS_ZEN_ENABLE", DEFAULT_ZEN_ENABLE
    ).lower() not in ("0", "false", "no")
    zen_reject_set = parse_int_set(
        getenv_str("SPAMHAUS_DQS_ZEN_REJECT_CODES", DEFAULT_ZEN_REJECT_CODES)
    )
    zen_reject_codes = tuple(sorted(zen_reject_set))

    ip_whitelist = parse_ip_set(
        getenv_str("SPAMHAUS_DQS_IP_WHITELIST", DEFAULT_IP_WHITELIST)
    )
    domain_whitelist = parse_csv_set(
        getenv_str("SPAMHAUS_DQS_DOMAIN_WHITELIST", DEFAULT_DOMAIN_WHITELIST)
    )
    domain_suffix_whitelist = parse_csv_set(
        getenv_str(
            "SPAMHAUS_DQS_DOMAIN_SUFFIX_WHITELIST", DEFAULT_DOMAIN_SUFFIX_WHITELIST
        )
    )
    whitelist_skip_all = getenv_str(
        "SPAMHAUS_DQS_WHITELIST_SKIP_ALL", DEFAULT_WHITELIST_SKIP_ALL
    ) in ("1", "true", "True", "yes", "Yes")

    cfg = Config(
        api_key=api_key,
        listen=listen,
        dns_per_try=dns_per_try,
        dns_lifetime=dns_lifetime,
        milter_timeout=milter_timeout,
        cache_max=cache_max,
        ttl_listed=ttl_listed,
        ttl_unlisted=ttl_unlisted,
        nameservers=nameservers,
        log_level=log_level,
        zen_enable=zen_enable,
        zen_reject_codes=zen_reject_codes,
        zen_reject_set=zen_reject_set,
        ip_whitelist=ip_whitelist,
        domain_whitelist=domain_whitelist,
        domain_suffix_whitelist=domain_suffix_whitelist,
        whitelist_skip_all=whitelist_skip_all,
    )

    configure_resolver(cfg.nameservers, cfg.dns_per_try, cfg.dns_lifetime)

    logger.info(
        "Starting milter listen=%s env_file=%s nameservers=%s dns_per_try=%s dns_lifetime=%s "
        "milter_timeout=%s log_level=%s zen_enable=%s zen_reject_codes=%s",
        cfg.listen,
        env_path,
        ",".join(cfg.nameservers),
        cfg.dns_per_try,
        cfg.dns_lifetime,
        cfg.milter_timeout,
        cfg.log_level,
        cfg.zen_enable,
        ",".join(str(x) for x in cfg.zen_reject_codes),
    )

    SpamhausDQSMilter.cfg = cfg
    Milter.factory = SpamhausDQSMilter
    Milter.runmilter("spamhaus_dqs_milter", cfg.listen, timeout=cfg.milter_timeout)


if __name__ == "__main__":
    main()
