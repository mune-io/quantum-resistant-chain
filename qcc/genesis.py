"""Генезис тестовой сети и генератор нагрузки."""

import random

from .chain import Tx
from .consensus import HONEST, Simulation, Validator
from .crypto import address


def make_validators(n, scheme, powers=None, behaviors=None):
    powers = powers or [100] * n
    behaviors = behaviors or {}
    out = []
    for i in range(n):
        pk, sk = scheme.keygen()
        out.append(Validator(i, powers[i], pk, sk, behaviors.get(i, HONEST)))
    return out


class Wallets:
    """Набор счетов, которые переводят друг другу средства."""

    def __init__(self, n, scheme, chain_id, balance=10**12, seed=1, key_in_state=True):
        self.scheme = scheme
        self.chain_id = chain_id
        self.keys = [scheme.keygen() for _ in range(n)]
        self.addresses = [address(scheme.alg_id, pk) for pk, _ in self.keys]
        self.nonces = [0] * n
        self.balance = balance
        self.rng = random.Random(seed)
        # True — ключ только в первой транзакции счёта, дальше он берётся из состояния
        self.key_in_state = key_in_state

    def genesis_balances(self):
        return {a: self.balance for a in self.addresses}

    def make_txs(self, count):
        txs = []
        for k in range(count):
            i = k % len(self.keys)
            pk, sk = self.keys[i]
            to = self.addresses[self.rng.randrange(len(self.addresses))]
            omit_key = self.key_in_state and self.nonces[i] > 0
            tx = Tx(
                self.scheme.alg_id,
                b"" if omit_key else pk,
                to,
                amount=1000,
                fee=10,
                nonce=self.nonces[i],
                from_addr=self.addresses[i],
            )
            tx.sign(sk, self.chain_id)
            self.nonces[i] += 1
            txs.append(tx)
        return txs


def make_network(n_validators, vote_scheme, tx_scheme, n_wallets=32, behaviors=None, key_in_state=True, **kw):
    chain_id = kw.pop("chain_id", b"qcc-sim")
    wallets = Wallets(n_wallets, tx_scheme, chain_id, key_in_state=key_in_state)
    sim = Simulation(
        make_validators(n_validators, vote_scheme, behaviors=behaviors),
        vote_scheme,
        wallets.genesis_balances(),
        chain_id=chain_id,
        **kw,
    )
    return sim, wallets
