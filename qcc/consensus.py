"""Минимальная модель консенсуса в стиле Tendermint.

Сеть синхронная: все сообщения раунда доставляются до таймаута, поэтому
честные узлы видят одно и то же, и модель исполняется в одном процессе.
Каждая подпись реально подписывается и проверяется. Проверка кэшируется
(как в реальной ноде: голос проверяется один раз при получении), поэтому
накопленное время проверок примерно равно нагрузке на CPU одного узла.
"""

import time
from dataclasses import dataclass, field, replace

from .chain import (
    DOMAIN_PROPOSAL,
    DOMAIN_TX,
    DOMAIN_VOTE,
    NIL,
    PRECOMMIT,
    PREVOTE,
    Block,
    Commit,
    Header,
    Proposal,
    Vote,
    merkle_root,
)
from .crypto import SCHEMES, sha3

HONEST = "honest"
OFFLINE = "offline"
EQUIVOCATE = "equivocate"  # голосует сразу за блок и за nil


# Стартовый лимит блока; поднимается через governance
MAX_BLOCK_BYTES = 2 * 1024 * 1024


class Halted(Exception):
    """Нет >2/3 силы голоса онлайн — сеть стоит, но безопасность сохранена."""


@dataclass
class Validator:
    index: int
    power: int
    pubkey: bytes
    secret: bytes
    behavior: str = HONEST
    # Состояние блокировки Tendermint, сбрасывается на каждой высоте
    locked_hash: bytes = None
    locked_round: int = -1
    valid_block: Block = None
    valid_round: int = -1


class ValidatorSet:
    def __init__(self, validators, scheme):
        self.validators = validators
        self.scheme = scheme
        self.total_power = sum(v.power for v in validators)
        # Строго больше 2/3
        self.quorum = self.total_power * 2 // 3 + 1
        self._hash = sha3(
            b"".join(
                bytes([scheme.alg_id]) + v.pubkey + v.power.to_bytes(8, "big")
                for v in validators
            )
        )

    def __len__(self):
        return len(self.validators)

    def __getitem__(self, i):
        return self.validators[i]

    def hash(self):
        return self._hash


class ProposerSelector:
    """Взвешенный round-robin из CometBFT: без VRF, полностью детерминирован."""

    def __init__(self, vset):
        self.vset = vset
        self.priority = [0] * len(vset)

    def _step(self, prio):
        for v in self.vset.validators:
            prio[v.index] += v.power
        best = max(range(len(prio)), key=lambda i: (prio[i], -i))
        prio[best] -= self.vset.total_power
        return best

    def proposer(self, round_):
        prio = list(self.priority)
        for _ in range(round_):
            self._step(prio)
        return self._step(prio)

    def advance(self, rounds_used):
        for _ in range(rounds_used):
            self._step(self.priority)


@dataclass
class Evidence:
    validator: int
    first: Vote
    second: Vote


class Verifier:
    """Проверка подписей с кэшем и учётом времени."""

    def __init__(self):
        self.seconds = 0.0
        self.count = 0
        self.seconds_by_domain = {}
        self._cache = {}

    def verify(self, scheme, pubkey, msg, sig, domain):
        key = (domain, pubkey, msg, sig)
        if key in self._cache:
            return self._cache[key]
        t = time.perf_counter()
        ok = scheme.verify(pubkey, msg, sig, domain)
        dt = time.perf_counter() - t
        self.seconds += dt
        self.seconds_by_domain[domain] = self.seconds_by_domain.get(domain, 0.0) + dt
        self.count += 1
        self._cache[key] = ok
        return ok

    def reset_cache(self):
        self._cache.clear()


class VoteSet:
    def __init__(self, sim, height, round_, kind):
        self.sim = sim
        self.height = height
        self.round = round_
        self.kind = kind
        self.votes = {}  # индекс валидатора -> Vote
        self.power = {}  # block_hash -> сила голоса

    def add(self, vote):
        """Возвращает True, если голос принят."""
        if (vote.height, vote.round, vote.kind) != (self.height, self.round, self.kind):
            return False
        if not 0 <= vote.validator < len(self.sim.vset):
            return False
        v = self.sim.vset[vote.validator]
        if not self.sim.verifier.verify(
            self.sim.vset.scheme,
            v.pubkey,
            vote.signing_bytes(self.sim.chain_id),
            vote.sig,
            DOMAIN_VOTE,
        ):
            return False
        prev = self.votes.get(vote.validator)
        if prev is not None:
            if prev.block_hash != vote.block_hash:
                self.sim.evidence.append(Evidence(vote.validator, prev, vote))
            return False
        self.votes[vote.validator] = vote
        self.power[vote.block_hash] = self.power.get(vote.block_hash, 0) + v.power
        return True

    def majority(self):
        """Хэш (или NIL), за который >2/3 силы, иначе None."""
        for h, p in self.power.items():
            if p >= self.sim.vset.quorum:
                return h
        return None


@dataclass
class HeightStats:
    height: int
    rounds: int
    proposer: int
    n_txs: int
    header_bytes: int
    txs_bytes: int
    commit_bytes: int
    block_bytes: int
    proposal_bytes: int
    vote_bytes: int
    rx_bytes_per_node: float
    verify_seconds: float
    vote_verify_seconds: float
    verify_count: int
    sign_seconds_per_validator: float
    evidence: int


@dataclass
class Account:
    balance: int
    nonce: int = 0
    # Ключ раскрывается и сохраняется при первой трате
    alg_id: int = None
    pubkey: bytes = b""


class Simulation:
    def __init__(
        self,
        validators,
        vote_scheme,
        balances,
        chain_id=b"qcc-sim",
        allowed_tx_algs=None,
        max_block_bytes=MAX_BLOCK_BYTES,
        block_time_ms=6000,
        timeout_ms=3000,
        max_rounds=20,
        commit_mode="all",
    ):
        self.chain_id = chain_id
        self.vset = ValidatorSet(validators, vote_scheme)
        self.selector = ProposerSelector(self.vset)
        self.allowed_tx_algs = allowed_tx_algs
        self.max_block_bytes = max_block_bytes
        self.block_time_ms = block_time_ms
        self.timeout_ms = timeout_ms
        self.max_rounds = max_rounds
        # "all" — подписи всех проголосовавших (как CometBFT),
        # "quorum" — минимальный набор, дающий >2/3 силы
        self.commit_mode = commit_mode
        self.accounts = {a: Account(b) for a, b in balances.items()}
        self.blocks = []
        self.commits = []
        self.evidence = []
        self.verifier = Verifier()
        self.time_ms = 0
        self._valid_blocks = {}

    # --- построение и проверка блоков ---

    def _select_txs(self, mempool, commit_bytes):
        budget = self.max_block_bytes - commit_bytes - 512
        picked, used = [], 0
        for tx in mempool:
            size = len(tx.encode()) + 4
            if used + size > budget:
                break
            picked.append(tx)
            used += size
        return picked

    def _build_block(self, proposer, round_, mempool):
        height = len(self.blocks) + 1
        last_commit = self.commits[-1] if self.commits else None
        txs = self._select_txs(mempool, len(last_commit.encode()) if last_commit else 0)
        header = Header(
            chain_id=self.chain_id,
            height=height,
            time_ms=self.time_ms + self.block_time_ms + round_ * self.timeout_ms,
            prev_hash=self.blocks[-1].hash() if self.blocks else bytes(32),
            proposer=proposer,
            tx_root=merkle_root([t.encode() for t in txs]),
            last_commit_hash=last_commit.hash() if last_commit else bytes(32),
            validators_hash=self.vset.hash(),
        )
        return Block(header, txs, last_commit)

    def verify_commit(self, commit, block_hash, height):
        if commit is None or commit.height != height or commit.block_hash != block_hash:
            return False
        if commit.n_validators != len(self.vset):
            return False
        power = 0
        for vote in commit.votes():
            v = self.vset[vote.validator]
            if not self.verifier.verify(
                self.vset.scheme, v.pubkey, vote.signing_bytes(self.chain_id), vote.sig, DOMAIN_VOTE
            ):
                return False
            power += v.power
        return power >= self.vset.quorum

    def _apply_txs(self, txs, accounts):
        """Применяет транзакции к копии состояния; False при любой ошибке."""
        for tx in txs:
            if self.allowed_tx_algs is not None and tx.alg_id not in self.allowed_tx_algs:
                return False
            sender = accounts.get(tx.sender)
            if sender is None:
                return False
            if sender.pubkey:
                # Ключ уже в состоянии: алгоритм счёта не меняется, повтор ключа допустим
                if tx.alg_id != sender.alg_id or tx.pubkey not in (b"", sender.pubkey):
                    return False
                pubkey = sender.pubkey
            elif tx.pubkey:
                pubkey = tx.pubkey
            else:
                return False
            if not self._verify_tx(tx, pubkey):
                return False
            if sender.nonce != tx.nonce or sender.balance < tx.amount + tx.fee:
                return False
            accounts[tx.sender] = replace(
                sender,
                balance=sender.balance - tx.amount - tx.fee,
                nonce=sender.nonce + 1,
                alg_id=tx.alg_id,
                pubkey=pubkey,
            )
            dest = accounts.get(tx.to, Account(0))
            accounts[tx.to] = replace(dest, balance=dest.balance + tx.amount)
        return True

    def _verify_tx(self, tx, pubkey):
        scheme = SCHEMES.get(tx.alg_id)
        if scheme is None:
            return False
        return self.verifier.verify(scheme, pubkey, tx.signing_bytes(self.chain_id), tx.sig, DOMAIN_TX)

    def validate_block(self, block, round_):
        h = block.hash()
        if h in self._valid_blocks:
            return self._valid_blocks[h]
        ok = self._validate_block(block, round_)
        self._valid_blocks[h] = ok
        return ok

    def _validate_block(self, block, round_):
        hd = block.header
        height = len(self.blocks) + 1
        if hd.chain_id != self.chain_id or hd.height != height:
            return False
        if hd.prev_hash != (self.blocks[-1].hash() if self.blocks else bytes(32)):
            return False
        if hd.validators_hash != self.vset.hash():
            return False
        if len(block.encode()) > self.max_block_bytes:
            return False
        if hd.tx_root != merkle_root([t.encode() for t in block.txs]):
            return False
        if height > 1:
            if hd.last_commit_hash != block.last_commit.hash():
                return False
            if not self.verify_commit(block.last_commit, hd.prev_hash, height - 1):
                return False
        accounts = dict(self.accounts)
        return self._apply_txs(block.txs, accounts)

    # --- раунды консенсуса ---

    def _sign_vote(self, v, kind, height, round_, block_hash, timing):
        vote = Vote(kind, height, round_, block_hash, v.index)
        t = time.perf_counter()
        vote.sig = self.vset.scheme.sign(v.secret, vote.signing_bytes(self.chain_id), DOMAIN_VOTE)
        timing[0] += time.perf_counter() - t
        return vote

    def _cast(self, voteset, v, kind, height, round_, block_hash, net, timing):
        choices = [block_hash]
        if v.behavior == EQUIVOCATE:
            choices.append(NIL if block_hash != NIL else b"\xff" * 32)
        for h in choices:
            vote = self._sign_vote(v, kind, height, round_, h, timing)
            net.broadcast(len(vote.encode()))
            voteset.add(vote)

    def produce_height(self, mempool):
        height = len(self.blocks) + 1
        net = _NetStats(sum(1 for v in self.vset.validators if v.behavior != OFFLINE))
        sign_timing = [0.0]
        verify_s0, verify_n0 = self.verifier.seconds, self.verifier.count
        vote_s0 = self._consensus_verify_seconds()
        evidence0 = len(self.evidence)
        polkas = {}
        for v in self.vset.validators:
            v.locked_hash, v.locked_round, v.valid_block, v.valid_round = None, -1, None, -1
        online = [v for v in self.vset.validators if v.behavior != OFFLINE]

        for round_ in range(self.max_rounds):
            proposer = self.selector.proposer(round_)
            pv = self.vset[proposer]
            proposal = None
            proposal_bytes = 0
            if pv.behavior != OFFLINE:
                if pv.valid_block is not None:
                    block, pol = pv.valid_block, pv.valid_round
                else:
                    block, pol = self._build_block(proposer, round_, mempool), -1
                proposal = Proposal(height, round_, pol, block, proposer)
                t = time.perf_counter()
                proposal.sig = self.vset.scheme.sign(
                    pv.secret, proposal.signing_bytes(self.chain_id), DOMAIN_PROPOSAL
                )
                sign_timing[0] += time.perf_counter() - t
                proposal_bytes = len(proposal.encode())
                net.broadcast(proposal_bytes, vote=False)

            ok_hash = None
            if proposal is not None:
                sig_ok = self.verifier.verify(
                    self.vset.scheme,
                    pv.pubkey,
                    proposal.signing_bytes(self.chain_id),
                    proposal.sig,
                    DOMAIN_PROPOSAL,
                )
                if sig_ok and proposal.block.header.proposer == proposer and self.validate_block(
                    proposal.block, round_
                ):
                    ok_hash = proposal.block.hash()

            prevotes = VoteSet(self, height, round_, PREVOTE)
            for v in online:
                target = NIL
                if ok_hash is not None:
                    unlocked_by_pol = (
                        proposal.pol_round > v.locked_round
                        and polkas.get(proposal.pol_round) == ok_hash
                    )
                    if v.locked_hash in (None, ok_hash) or unlocked_by_pol:
                        target = ok_hash
                self._cast(prevotes, v, PREVOTE, height, round_, target, net, sign_timing)

            polka = prevotes.majority()
            polkas[round_] = polka
            precommits = VoteSet(self, height, round_, PRECOMMIT)
            for v in online:
                target = NIL
                if polka is not None and polka != NIL and polka == ok_hash:
                    v.locked_hash, v.locked_round = polka, round_
                    v.valid_block, v.valid_round = proposal.block, round_
                    target = polka
                self._cast(precommits, v, PRECOMMIT, height, round_, target, net, sign_timing)

            decided = precommits.majority()
            if decided is not None and decided != NIL:
                block = proposal.block
                signers = [i for i, vt in precommits.votes.items() if vt.block_hash == decided]
                if self.commit_mode == "quorum":
                    signers = self._quorum_subset(signers)
                commit = Commit(
                    height,
                    round_,
                    decided,
                    len(self.vset),
                    {i: precommits.votes[i].sig for i in signers},
                )
                self._commit(block, commit, round_)
                header, txs, last_commit = block.encode_parts()
                return HeightStats(
                    height=height,
                    rounds=round_ + 1,
                    proposer=proposer,
                    n_txs=len(block.txs),
                    header_bytes=len(header),
                    txs_bytes=len(txs),
                    commit_bytes=len(last_commit),
                    block_bytes=len(header) + len(txs) + len(last_commit),
                    proposal_bytes=proposal_bytes,
                    vote_bytes=net.vote_sent,
                    rx_bytes_per_node=net.rx_per_node(),
                    verify_seconds=self.verifier.seconds - verify_s0,
                    vote_verify_seconds=self._consensus_verify_seconds() - vote_s0,
                    verify_count=self.verifier.count - verify_n0,
                    sign_seconds_per_validator=sign_timing[0] / max(1, len(online)),
                    evidence=len(self.evidence) - evidence0,
                )
            # Таймаут раунда — переходим к следующему лидеру
        raise Halted(f"высота {height}: нет решения за {self.max_rounds} раундов")

    def _quorum_subset(self, signers):
        """Меньше всего подписей: берём валидаторов с наибольшей силой голоса."""
        picked, power = [], 0
        for i in sorted(signers, key=lambda i: (-self.vset[i].power, i)):
            if power >= self.vset.quorum:
                break
            picked.append(i)
            power += self.vset[i].power
        return picked

    def _consensus_verify_seconds(self):
        d = self.verifier.seconds_by_domain
        return d.get(DOMAIN_VOTE, 0.0) + d.get(DOMAIN_PROPOSAL, 0.0)

    def _commit(self, block, commit, round_):
        self._apply_txs(block.txs, self.accounts)
        self.blocks.append(block)
        self.commits.append(commit)
        self.time_ms = block.header.time_ms
        self.selector.advance(round_ + 1)
        self._valid_blocks.clear()
        self.verifier.reset_cache()


class _NetStats:
    """Трафик без учёта дублей gossip — это нижняя оценка."""

    def __init__(self, n_online):
        self.n_online = n_online
        self.sent = 0
        self.vote_sent = 0

    def broadcast(self, size, vote=True):
        self.sent += size
        if vote:
            self.vote_sent += size

    def rx_per_node(self):
        # Каждый узел получает всё, кроме своих сообщений
        return self.sent * (self.n_online - 1) / max(1, self.n_online)
