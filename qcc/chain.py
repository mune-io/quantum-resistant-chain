"""Структуры цепи и их детерминированное бинарное кодирование.

Кодирование близко к protobuf (varint-длины), чтобы замеры размеров
блоков были реалистичными, а не размерами Python-объектов.
"""

from dataclasses import dataclass, field

from .crypto import SCHEMES, address, sha3

DOMAIN_TX = b"qcc/tx/v1"
DOMAIN_VOTE = b"qcc/vote/v1"
DOMAIN_PROPOSAL = b"qcc/proposal/v1"

PREVOTE = 1
PRECOMMIT = 2

NIL = b""


def uvarint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_bytes(b):
    return uvarint(len(b)) + b


def merkle_root(leaves):
    """Корень Меркла с префиксами листьев/узлов (как в RFC 6962)."""
    if not leaves:
        return sha3(b"")
    level = [sha3(b"\x00" + leaf) for leaf in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(sha3(b"\x01" + level[i] + level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


@dataclass
class Tx:
    """Перевод. pubkey нужен только при первой трате со счёта.

    После неё ключ хранится в состоянии аккаунта, и транзакция несёт лишь
    20-байтовый адрес отправителя (from_addr) вместо ключа.
    """

    alg_id: int
    pubkey: bytes  # b"" — ключ берётся из состояния
    to: bytes
    amount: int
    fee: int
    nonce: int
    sig: bytes = b""
    from_addr: bytes = b""

    def signing_bytes(self, chain_id):
        # Подписывается адрес, а не ключ: адрес уже фиксирует (alg_id, pubkey),
        # поэтому подпись одинакова в обеих формах транзакции
        return (
            enc_bytes(chain_id)
            + bytes([self.alg_id])
            + self.sender
            + enc_bytes(self.to)
            + uvarint(self.amount)
            + uvarint(self.fee)
            + uvarint(self.nonce)
        )

    def encode(self):
        # chain_id не хранится в транзакции — он входит только в подписываемые байты
        return (
            bytes([self.alg_id])
            + enc_bytes(self.pubkey)
            + (b"" if self.pubkey else self.from_addr)
            + enc_bytes(self.to)
            + uvarint(self.amount)
            + uvarint(self.fee)
            + uvarint(self.nonce)
            + enc_bytes(self.sig)
        )

    @property
    def sender(self):
        return address(self.alg_id, self.pubkey) if self.pubkey else self.from_addr

    def sign(self, sk, chain_id):
        self.sig = SCHEMES[self.alg_id].sign(sk, self.signing_bytes(chain_id), DOMAIN_TX)

    def verify(self, chain_id, pubkey=None):
        """pubkey — ключ из состояния, если в транзакции его нет."""
        scheme = SCHEMES.get(self.alg_id)
        pk = self.pubkey or pubkey
        return scheme is not None and bool(pk) and scheme.verify(
            pk, self.signing_bytes(chain_id), self.sig, DOMAIN_TX
        )


@dataclass
class Vote:
    kind: int
    height: int
    round: int
    block_hash: bytes  # NIL — голос "против"
    validator: int
    sig: bytes = b""

    def signing_bytes(self, chain_id):
        return (
            enc_bytes(chain_id)
            + bytes([self.kind])
            + uvarint(self.height)
            + uvarint(self.round)
            + enc_bytes(self.block_hash)
            + uvarint(self.validator)
        )

    def encode(self):
        return (
            bytes([self.kind])
            + uvarint(self.height)
            + uvarint(self.round)
            + enc_bytes(self.block_hash)
            + uvarint(self.validator)
            + enc_bytes(self.sig)
        )


@dataclass
class Commit:
    """Доказательство финальности: precommit-подписи >2/3 силы голоса.

    Индексы валидаторов задаются битовой маской, а не списком.
    """

    height: int
    round: int
    block_hash: bytes
    n_validators: int
    sigs: dict = field(default_factory=dict)  # индекс валидатора -> подпись

    def bitmap(self):
        bits = bytearray((self.n_validators + 7) // 8)
        for i in self.sigs:
            bits[i // 8] |= 1 << (i % 8)
        return bytes(bits)

    def encode(self):
        out = (
            uvarint(self.height)
            + uvarint(self.round)
            + enc_bytes(self.block_hash)
            + uvarint(self.n_validators)
            + self.bitmap()
        )
        for i in sorted(self.sigs):
            out += enc_bytes(self.sigs[i])
        return out

    def hash(self):
        return sha3(self.encode())

    def votes(self):
        for i in sorted(self.sigs):
            yield Vote(PRECOMMIT, self.height, self.round, self.block_hash, i, self.sigs[i])


@dataclass
class Header:
    chain_id: bytes
    height: int
    time_ms: int
    prev_hash: bytes
    proposer: int
    tx_root: bytes
    last_commit_hash: bytes
    validators_hash: bytes

    def encode(self):
        return (
            enc_bytes(self.chain_id)
            + uvarint(self.height)
            + uvarint(self.time_ms)
            + enc_bytes(self.prev_hash)
            + uvarint(self.proposer)
            + enc_bytes(self.tx_root)
            + enc_bytes(self.last_commit_hash)
            + enc_bytes(self.validators_hash)
        )


@dataclass
class Block:
    header: Header
    txs: list
    last_commit: Commit = None  # None только у первого блока

    def hash(self):
        return sha3(self.header.encode())

    def encode_parts(self):
        """Размеры частей блока: заголовок, транзакции, commit предыдущего."""
        txs = b"".join(enc_bytes(t.encode()) for t in self.txs)
        commit = self.last_commit.encode() if self.last_commit else b""
        return self.header.encode(), uvarint(len(self.txs)) + txs, enc_bytes(commit)

    def encode(self):
        return b"".join(self.encode_parts())


@dataclass
class Proposal:
    height: int
    round: int
    pol_round: int  # -1, если у блока нет polka из прошлого раунда
    block: Block
    proposer: int
    sig: bytes = b""

    def signing_bytes(self, chain_id):
        return (
            enc_bytes(chain_id)
            + uvarint(self.height)
            + uvarint(self.round)
            + uvarint(self.pol_round + 1)
            + enc_bytes(self.block.hash())
        )

    def encode(self):
        return (
            uvarint(self.height)
            + uvarint(self.round)
            + uvarint(self.pol_round + 1)
            + enc_bytes(self.block.encode())
            + uvarint(self.proposer)
            + enc_bytes(self.sig)
        )
