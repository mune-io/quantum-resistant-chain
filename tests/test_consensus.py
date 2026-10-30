import unittest
from dataclasses import replace

from qcc.chain import DOMAIN_TX, NIL, PRECOMMIT, Tx, Vote
from qcc.consensus import EQUIVOCATE, OFFLINE, Halted, VoteSet
from qcc.crypto import (
    ED25519,
    FALCON_512,
    HYBRID_ED25519_FALCON_512,
    HYBRID_ED25519_ML_DSA_44,
    ML_DSA_44,
    SLH_DSA_128S,
)
from qcc.genesis import make_network

REAL_SCHEMES = [ED25519, FALCON_512, ML_DSA_44, SLH_DSA_128S, HYBRID_ED25519_ML_DSA_44, HYBRID_ED25519_FALCON_512]


class TestSignatures(unittest.TestCase):
    def test_sign_verify_and_reject_tamper(self):
        for s in REAL_SCHEMES:
            with self.subTest(s.name):
                pk, sk = s.keygen()
                sig = s.sign(sk, b"msg", DOMAIN_TX)
                self.assertLessEqual(len(sig), s.sig_size)
                self.assertTrue(s.verify(pk, b"msg", sig, DOMAIN_TX))
                self.assertFalse(s.verify(pk, b"msG", sig, DOMAIN_TX))
                self.assertFalse(s.verify(pk, b"msg", sig, b"other-domain"))

    def test_hybrid_needs_both_parts(self):
        h = HYBRID_ED25519_ML_DSA_44
        pk, sk = h.keygen()
        sig = h.sign(sk, b"m", DOMAIN_TX)
        broken_classic = bytes(64) + sig[64:]
        broken_pq = sig[:64] + bytes(len(sig) - 64)
        self.assertFalse(h.verify(pk, b"m", broken_classic, DOMAIN_TX))
        self.assertFalse(h.verify(pk, b"m", broken_pq, DOMAIN_TX))

    def test_falcon_votes_commit_chain(self):
        sim, wallets = make_network(7, HYBRID_ED25519_FALCON_512, HYBRID_ED25519_ML_DSA_44, n_wallets=4)
        for _ in range(3):
            sim.produce_height(wallets.make_txs(4))
        self.assertTrue(sim.verify_commit(sim.blocks[2].last_commit, sim.blocks[1].hash(), 2))

    def test_hybrid_part_cannot_be_stripped(self):
        # PQ-часть гибридной подписи не проходит как одиночная ML-DSA подпись
        h = HYBRID_ED25519_ML_DSA_44
        pk, sk = h.keygen()
        sig = h.sign(sk, b"m", DOMAIN_TX)
        self.assertFalse(ML_DSA_44.verify(pk[32:], b"m", sig[64:], DOMAIN_TX))
        self.assertFalse(ED25519.verify(pk[:32], b"m", sig[:64], DOMAIN_TX))


class TestConsensus(unittest.TestCase):
    def setUp(self):
        self.sim, self.wallets = make_network(7, HYBRID_ED25519_ML_DSA_44, HYBRID_ED25519_ML_DSA_44, n_wallets=8)

    def test_commits_chain_and_applies_txs(self):
        for _ in range(3):
            st = self.sim.produce_height(self.wallets.make_txs(10))
            self.assertEqual(st.rounds, 1)
            self.assertEqual(st.n_txs, 10)
        self.assertEqual(len(self.sim.blocks), 3)
        # Блок 2 несёт commit блока 1, и он проверяется
        b2 = self.sim.blocks[1]
        self.assertTrue(self.sim.verify_commit(b2.last_commit, self.sim.blocks[0].hash(), 1))
        sender = self.sim.accounts[self.wallets.addresses[0]]
        self.assertEqual(sender.nonce, 6)  # по 2 tx (k=0, k=8) за каждый из 3 блоков

    def test_forged_vote_rejected(self):
        vs = VoteSet(self.sim, 1, 0, PRECOMMIT)
        vote = Vote(PRECOMMIT, 1, 0, b"\x01" * 32, 0, sig=bytes(HYBRID_ED25519_ML_DSA_44.sig_size))
        self.assertFalse(vs.add(vote))
        self.assertEqual(vs.power, {})

    def test_commit_with_too_few_sigs_rejected(self):
        self.sim.produce_height(self.wallets.make_txs(1))
        commit = self.sim.commits[-1]
        weak = replace(commit, sigs=dict(list(commit.sigs.items())[:4]))  # 4 из 7 < 2/3
        self.assertFalse(self.sim.verify_commit(weak, commit.block_hash, 1))


class TestKeyInState(unittest.TestCase):
    def setUp(self):
        self.sim, self.wallets = make_network(4, ED25519, HYBRID_ED25519_FALCON_512, n_wallets=2, max_rounds=3)

    def test_key_revealed_once_then_taken_from_state(self):
        first = self.wallets.make_txs(2)
        self.assertTrue(all(t.pubkey for t in first))
        self.sim.produce_height(first)
        second = self.wallets.make_txs(2)
        self.assertTrue(all(not t.pubkey for t in second))
        self.sim.produce_height(second)
        acc = self.sim.accounts[self.wallets.addresses[0]]
        self.assertEqual(acc.nonce, 2)
        self.assertEqual(acc.pubkey, self.wallets.keys[0][0])
        self.assertLess(len(second[0].encode()), len(first[0].encode()) - 900)

    def test_keyless_tx_from_unrevealed_account_rejected(self):
        tx = self.wallets.make_txs(1)[0]
        tx = replace(tx, pubkey=b"")
        with self.assertRaises(Halted):
            self.sim.produce_height([tx])

    def test_spoofed_sender_rejected(self):
        self.sim.produce_height(self.wallets.make_txs(2))
        victim = self.wallets.addresses[0]
        _, attacker_sk = HYBRID_ED25519_FALCON_512.keygen()
        tx = Tx(HYBRID_ED25519_FALCON_512.alg_id, b"", victim, 1000, 10, 1, from_addr=victim)
        tx.sign(attacker_sk, self.sim.chain_id)
        with self.assertRaises(Halted):
            self.sim.produce_height([tx])

    def test_algorithm_switch_on_revealed_account_rejected(self):
        self.sim.produce_height(self.wallets.make_txs(2))
        tx = self.wallets.make_txs(1)[0]
        tx = replace(tx, alg_id=ML_DSA_44.alg_id)
        with self.assertRaises(Halted):
            self.sim.produce_height([tx])


class TestQuorumCommit(unittest.TestCase):
    def test_commit_trimmed_to_quorum_is_valid(self):
        sim, wallets = make_network(7, FALCON_512, ED25519, n_wallets=2, commit_mode="quorum")
        for _ in range(3):
            sim.produce_height(wallets.make_txs(2))
        commit = sim.blocks[2].last_commit
        self.assertEqual(len(commit.sigs), 5)  # 5 * 100 > 2/3 * 700
        self.assertTrue(sim.verify_commit(commit, sim.blocks[1].hash(), 2))


class TestFaults(unittest.TestCase):
    def test_tampered_tx_block_never_commits(self):
        sim, wallets = make_network(4, ED25519, ED25519, n_wallets=4, max_rounds=3)
        txs = wallets.make_txs(3)
        txs[1] = replace(txs[1], amount=txs[1].amount + 1)
        with self.assertRaises(Halted):
            sim.produce_height(txs)
        self.assertEqual(sim.blocks, [])

    def test_up_to_one_third_offline_still_live(self):
        # 10 из 31 офлайн: 21*100 = 2100 > 2/3*3100 → сеть идёт
        behaviors = {i: OFFLINE for i in range(10)}
        sim, wallets = make_network(31, ED25519, ED25519, behaviors=behaviors)
        rounds = [sim.produce_height(wallets.make_txs(2)).rounds for _ in range(31)]
        self.assertEqual(len(sim.blocks), 31)
        # Когда лидер офлайн — смена раунда
        self.assertGreater(max(rounds), 1)

    def test_more_than_one_third_offline_halts(self):
        behaviors = {i: OFFLINE for i in range(11)}
        sim, wallets = make_network(31, ED25519, ED25519, behaviors=behaviors, max_rounds=5)
        with self.assertRaises(Halted):
            sim.produce_height(wallets.make_txs(2))
        self.assertEqual(sim.blocks, [])

    def test_equivocation_detected(self):
        sim, wallets = make_network(4, ED25519, ED25519, behaviors={2: EQUIVOCATE})
        st = sim.produce_height(wallets.make_txs(1))
        self.assertGreaterEqual(st.evidence, 2)  # prevote и precommit
        self.assertTrue(all(e.validator == 2 for e in sim.evidence))
        self.assertNotIn(NIL, [sim.commits[-1].block_hash])


if __name__ == "__main__":
    unittest.main()
