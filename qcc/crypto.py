"""Схемы подписей: классическая, постквантовая и гибридная.

Каждая схема имеет alg_id — он попадает в транзакции и голоса, и в
доменный контекст подписи. Так протокол может менять алгоритмы через
версионирование, а гибридную подпись нельзя "разобрать" на части и
выдать за одиночную.
"""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
import pqcrypto
from pqcrypto.sign import ml_dsa_44, ml_dsa_65, slh_dsa_sha2_128s

from . import oqs

ALG_ED25519 = 0x01
ALG_ML_DSA_44 = 0x10
ALG_ML_DSA_65 = 0x11
ALG_SLH_DSA_128S = 0x20
ALG_FALCON_512 = 0x30
ALG_HYBRID_ED25519_ML_DSA_44 = 0x80
ALG_HYBRID_ED25519_FALCON_512 = 0x81


def _context(domain, alg_id):
    return domain + b"/" + bytes([alg_id])


class Scheme:
    alg_id = 0
    name = ""
    pk_size = 0
    sig_size = 0

    def keygen(self):
        raise NotImplementedError

    def sign(self, sk, msg, domain):
        raise NotImplementedError

    def verify(self, pk, msg, sig, domain):
        raise NotImplementedError


class Ed25519(Scheme):
    alg_id = ALG_ED25519
    name = "Ed25519"
    pk_size = 32
    sig_size = 64

    def keygen(self):
        sk = Ed25519PrivateKey.generate()
        raw = serialization.Encoding.Raw
        pk = sk.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
        skb = sk.private_bytes(
            raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        return pk, skb

    def sign(self, sk, msg, domain):
        ctx = _context(domain, self.alg_id)
        return Ed25519PrivateKey.from_private_bytes(sk).sign(
            bytes([len(ctx)]) + ctx + msg
        )

    def verify(self, pk, msg, sig, domain):
        if len(pk) != self.pk_size or len(sig) != self.sig_size:
            return False
        ctx = _context(domain, self.alg_id)
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(
                sig, bytes([len(ctx)]) + ctx + msg
            )
            return True
        except InvalidSignature:
            return False


class _PqcryptoScheme(Scheme):
    """Обёртка над FIPS 204/205 схемами из pqcrypto (контекст — штатный)."""

    module = None

    def __init__(self):
        self.pk_size = self.module.PUBLIC_KEY_SIZE
        self.sig_size = self.module.SIGNATURE_SIZE

    def keygen(self):
        return self.module.keygen()

    def sign(self, sk, msg, domain):
        return self.module.sign(sk, msg, context=_context(domain, self.alg_id))

    def verify(self, pk, msg, sig, domain):
        if len(pk) != self.pk_size or len(sig) != self.sig_size:
            return False
        try:
            self.module.verify(pk, msg, sig, context=_context(domain, self.alg_id))
            return True
        except pqcrypto.InvalidSignatureError:
            return False


class _OqsScheme(Scheme):
    """Схема из liboqs. Без поддержки FIPS-контекста домен идёт префиксом сообщения."""

    oqs_name = ""
    # Подпись переменной длины (Falcon): sig_size — максимум
    variable = False

    def __init__(self):
        self._sig = oqs.Sig(self.oqs_name)
        self.pk_size = self._sig.pk_size
        self.sig_size = self._sig.max_sig_size

    def _args(self, msg, domain):
        ctx = _context(domain, self.alg_id)
        if self._sig.ctx_support:
            return msg, ctx
        return bytes([len(ctx)]) + ctx + msg, None

    def keygen(self):
        return self._sig.keypair()

    def sign(self, sk, msg, domain):
        return self._sig.sign(sk, *self._args(msg, domain))

    def verify(self, pk, msg, sig, domain):
        bad_len = len(sig) > self.sig_size if self.variable else len(sig) != self.sig_size
        if len(pk) != self.pk_size or bad_len:
            return False
        m, ctx = self._args(msg, domain)
        return self._sig.verify(pk, m, sig, ctx)


# ML-DSA: liboqs (AVX2) быстрее pqcrypto в разы; формат FIPS 204 у них совместим
if oqs.available("ML-DSA-44"):

    class MLDSA44(_OqsScheme):
        alg_id = ALG_ML_DSA_44
        name = "ML-DSA-44"
        oqs_name = "ML-DSA-44"

    class MLDSA65(_OqsScheme):
        alg_id = ALG_ML_DSA_65
        name = "ML-DSA-65"
        oqs_name = "ML-DSA-65"

else:

    class MLDSA44(_PqcryptoScheme):
        alg_id = ALG_ML_DSA_44
        name = "ML-DSA-44"
        module = ml_dsa_44

    class MLDSA65(_PqcryptoScheme):
        alg_id = ALG_ML_DSA_65
        name = "ML-DSA-65"
        module = ml_dsa_65


class SLHDSA128s(_PqcryptoScheme):
    alg_id = ALG_SLH_DSA_128S
    name = "SLH-DSA-128s"
    module = slh_dsa_sha2_128s


class Falcon512(_OqsScheme):
    alg_id = ALG_FALCON_512
    name = "Falcon-512"
    oqs_name = "Falcon-512"
    variable = True


class Hybrid(Scheme):
    """Классическая + постквантовая подпись; валидна, только если валидны обе."""

    def __init__(self, alg_id, name, classic, pq):
        self.alg_id = alg_id
        self.name = name
        self.classic = classic
        self.pq = pq
        self.pk_size = classic.pk_size + pq.pk_size
        self.sig_size = classic.sig_size + pq.sig_size

    def keygen(self):
        cpk, csk = self.classic.keygen()
        qpk, qsk = self.pq.keygen()
        return cpk + qpk, (len(csk).to_bytes(2, "big") + csk + qsk)

    def _split_sk(self, sk):
        n = int.from_bytes(sk[:2], "big")
        return sk[2 : 2 + n], sk[2 + n :]

    def _hybrid_domain(self, domain):
        # Обе части подписывают домен с alg_id гибрида — strip-атака не пройдёт
        return _context(domain, self.alg_id)

    def sign(self, sk, msg, domain):
        csk, qsk = self._split_sk(sk)
        d = self._hybrid_domain(domain)
        return self.classic.sign(csk, msg, d) + self.pq.sign(qsk, msg, d)

    def verify(self, pk, msg, sig, domain):
        # Классическая часть фиксированной длины, PQ-часть может быть переменной
        if len(pk) != self.pk_size or not self.classic.sig_size < len(sig) <= self.sig_size:
            return False
        c = self.classic
        d = self._hybrid_domain(domain)
        ok_classic = c.verify(pk[: c.pk_size], msg, sig[: c.sig_size], d)
        ok_pq = self.pq.verify(pk[c.pk_size :], msg, sig[c.sig_size :], d)
        return ok_classic and ok_pq


ED25519 = Ed25519()
ML_DSA_44 = MLDSA44()
ML_DSA_65 = MLDSA65()
SLH_DSA_128S = SLHDSA128s()
FALCON_512 = Falcon512()
HYBRID_ED25519_ML_DSA_44 = Hybrid(
    ALG_HYBRID_ED25519_ML_DSA_44, "Ed25519+ML-DSA-44", ED25519, ML_DSA_44
)
HYBRID_ED25519_FALCON_512 = Hybrid(
    ALG_HYBRID_ED25519_FALCON_512, "Ed25519+Falcon-512", ED25519, FALCON_512
)

SCHEMES = {
    s.alg_id: s
    for s in (
        ED25519,
        ML_DSA_44,
        ML_DSA_65,
        SLH_DSA_128S,
        FALCON_512,
        HYBRID_ED25519_ML_DSA_44,
        HYBRID_ED25519_FALCON_512,
    )
}


def sha3(data):
    return hashlib.sha3_256(data).digest()


def address(alg_id, pubkey):
    """Адрес = хэш от (alg_id, pubkey): ключ раскрывается только при трате."""
    return sha3(bytes([alg_id]) + pubkey)[:20]
