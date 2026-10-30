"""Замеры: подписи, размер блоков и трафик при разных схемах и числе валидаторов.

Запуск: .venv/bin/python bench.py  → печатает отчёт и пишет results/report.md
"""

import pathlib
import statistics
import sys
import time

from qcc.chain import DOMAIN_TX, Tx
from qcc.consensus import MAX_BLOCK_BYTES, OFFLINE, Halted
from qcc.crypto import (
    ED25519,
    FALCON_512,
    HYBRID_ED25519_FALCON_512,
    HYBRID_ED25519_ML_DSA_44,
    ML_DSA_44,
    ML_DSA_65,
    SLH_DSA_128S,
    address,
)
from qcc.genesis import make_network

BLOCK_TIME_S = 6
BLOCKS_PER_DAY = 86400 // BLOCK_TIME_S
TXS_PER_BLOCK = 100
VALIDATOR_COUNTS = [4, 21, 31, 64, 100, 150]
VOTE_SCHEMES = [ED25519, FALCON_512, HYBRID_ED25519_FALCON_512, ML_DSA_44, HYBRID_ED25519_ML_DSA_44]
TX_SCHEMES = [ED25519, FALCON_512, HYBRID_ED25519_FALCON_512, ML_DSA_44, HYBRID_ED25519_ML_DSA_44, ML_DSA_65, SLH_DSA_128S]
HEIGHTS = 4  # первый блок без commit, усредняем по остальным

out_lines = []


def emit(line=""):
    print(line)
    out_lines.append(line)


def table(headers, rows):
    emit("| " + " | ".join(headers) + " |")
    emit("|" + "|".join("---" for _ in headers) + "|")
    for r in rows:
        emit("| " + " | ".join(str(c) for c in r) + " |")
    emit()


def kb(n):
    return f"{n / 1024:,.1f}"


def gb(n):
    return f"{n / 1024**3:,.2f}"


def timeit(fn, repeat):
    t = time.perf_counter()
    for _ in range(repeat):
        fn()
    return (time.perf_counter() - t) / repeat * 1e6


def bench_signatures():
    emit("## 1. Подписи: размеры и скорость (одно ядро)")
    emit()
    rows = []
    msg = bytes(200)
    for s in [ED25519, FALCON_512, HYBRID_ED25519_FALCON_512, ML_DSA_44, HYBRID_ED25519_ML_DSA_44, ML_DSA_65, SLH_DSA_128S]:
        pk, sk = s.keygen()
        sig = s.sign(sk, msg, DOMAIN_TX)
        rep = 20 if s is SLH_DSA_128S else 300
        sign_us = timeit(lambda: s.sign(sk, msg, DOMAIN_TX), rep)
        verify_us = timeit(lambda: s.verify(pk, msg, sig, DOMAIN_TX), rep)
        sizes = [len(s.sign(sk, i.to_bytes(4, "big"), DOMAIN_TX)) for i in range(rep)]
        rows.append((s.name, s.pk_size, f"{statistics.mean(sizes):,.0f}", s.sig_size, f"{sign_us:,.0f}", f"{verify_us:,.0f}"))
    table(["Схема", "Pubkey, Б", "Подпись (средн.), Б", "Подпись (макс.), Б", "Подпись, мкс", "Проверка, мкс"], rows)


def bench_tx_sizes():
    emit("## 2. Размер транзакции и пропускная способность")
    emit()
    emit(f"Лимит блока {MAX_BLOCK_BYTES // 1024**2} МБ, блок раз в {BLOCK_TIME_S} с; commit для 100 валидаторов (гибрид) вычтен из лимита.")
    emit()
    emit("«Первая трата» несёт публичный ключ; «повторная» — только адрес отправителя, ключ берётся из состояния.")
    emit()
    commit_reserve = 100 * (HYBRID_ED25519_ML_DSA_44.sig_size + 3) + 64
    rows = []
    for s in TX_SCHEMES:
        pk, sk = s.keygen()
        sizes = []
        for key in (pk, b""):
            tx = Tx(s.alg_id, key, address(s.alg_id, pk), 10**9, 1000, 12345, from_addr=address(s.alg_id, pk))
            tx.sign(sk, b"qcc-sim")
            sizes.append(len(tx.encode()))
        tps = [max_tps(size, commit_reserve) for size in sizes]
        rows.append((s.name, sizes[0], sizes[1], f"{(1 - sizes[1] / sizes[0]) * 100:.0f}%", f"{tps[0]:,.0f}", f"{tps[1]:,.0f}"))
    table(
        ["Схема транзакции", "Первая трата, Б", "Повторная, Б", "Экономия", "Макс. TPS (первая)", "Макс. TPS (повторная)"],
        rows,
    )


def max_tps(tx_size, commit_bytes):
    per_block = (MAX_BLOCK_BYTES - commit_bytes - 512) // (tx_size + 4)
    return per_block / BLOCK_TIME_S


def run_heights(n, vote_scheme, tx_scheme, behaviors=None, heights=HEIGHTS, txs=TXS_PER_BLOCK, key_in_state=False, **kw):
    sim, wallets = make_network(n, vote_scheme, tx_scheme, n_wallets=32, behaviors=behaviors, key_in_state=key_in_state, **kw)
    stats = [sim.produce_height(wallets.make_txs(txs)) for _ in range(heights)]
    return sim, stats[1:]


def bench_matrix():
    emit("## 3. Блоки и трафик: схема голосов × число валидаторов")
    emit()
    emit(
        f"Базовая линия без оптимизаций: транзакции — гибрид Ed25519+ML-DSA-44 с ключом в каждой tx, {TXS_PER_BLOCK} tx в блоке. "
        "«Commit» — precommit-подписи всех проголосовавших за предыдущий блок (как в CometBFT), они лежат в каждом блоке. "
        "Трафик — сколько один узел получает за высоту (предложение блока + все голоса), без дублей gossip. "
        "CPU — проверка голосов одним узлом за высоту."
    )
    emit()
    results = {}
    rows = []
    for vs in VOTE_SCHEMES:
        for n in VALIDATOR_COUNTS:
            _, st = run_heights(n, vs, HYBRID_ED25519_ML_DSA_44)
            commit = statistics.mean(s.commit_bytes for s in st)
            block = statistics.mean(s.block_bytes for s in st)
            rx = statistics.mean(s.rx_bytes_per_node for s in st)
            vote_rx = statistics.mean(s.vote_bytes for s in st) * (n - 1) / n
            cpu = statistics.mean(s.vote_verify_seconds for s in st) * 1000
            results[(vs.name, n)] = dict(commit=commit, block=block, rx=rx, cpu=cpu)
            rows.append(
                (
                    vs.name,
                    n,
                    kb(commit),
                    kb(block),
                    f"{commit / block * 100:.0f}%",
                    gb(commit * BLOCKS_PER_DAY),
                    kb(vote_rx),
                    kb(rx),
                    f"{cpu:,.1f}",
                )
            )
            print(f"  … {vs.name}, n={n}", file=sys.stderr)
    table(
        [
            "Подпись голосов",
            "Валидаторов",
            "Commit, КБ",
            "Блок, КБ",
            "Доля commit",
            "Commit/сутки, ГБ",
            "Голоса rx/высота, КБ",
            "Всего rx/высота, КБ",
            "CPU голоса, мс",
        ],
        rows,
    )
    return results


def bench_pruning(results):
    emit("## 4. Рост цепи за год и эффект pruning старых commit-подписей")
    emit()
    emit(
        "Pruning: полные commit хранятся за последние сутки и по одному на эпоху (сутки) — для лёгких клиентов "
        "и защиты от long-range атак. Остальная цепь — заголовки и транзакции."
    )
    emit()
    rows = []
    for name in [s.name for s in VOTE_SCHEMES]:
        for n in (31, 100, 150):
            r = results[(name, n)]
            per_year_full = r["block"] * BLOCKS_PER_DAY * 365
            body = r["block"] - r["commit"]
            per_year_pruned = (body * BLOCKS_PER_DAY + r["commit"]) * 365 + r["commit"] * BLOCKS_PER_DAY
            rows.append((name, n, gb(per_year_full), gb(per_year_pruned), f"{(1 - per_year_pruned / per_year_full) * 100:.0f}%"))
    table(["Подпись голосов", "Валидаторов", "Год без pruning, ГБ", "Год с pruning, ГБ", "Экономия"], rows)


def bench_faults():
    emit("## 5. Отказы (31 валидатор, гибридные подписи)")
    emit()
    rows = []
    for label, behaviors, heights in [
        ("все онлайн", {}, 31),
        ("10 офлайн вразброс (< 1/3)", {i * 3: OFFLINE for i in range(10)}, 31),
        ("10 офлайн подряд (< 1/3)", {i: OFFLINE for i in range(10)}, 31),
        ("11 офлайн (> 1/3)", {i * 2: OFFLINE for i in range(11)}, 1),
    ]:
        sim, wallets = make_network(31, HYBRID_ED25519_ML_DSA_44, ED25519, n_wallets=8, behaviors=behaviors, max_rounds=40)
        try:
            st = [sim.produce_height(wallets.make_txs(5)) for _ in range(heights)]
            rounds = [s.rounds for s in st]
            avg_s = (sim.time_ms / len(st)) / 1000
            rows.append((label, f"{len(st)} блоков", f"{statistics.mean(rounds):.2f}", max(rounds), f"{avg_s:.1f}"))
        except Halted:
            rows.append((label, "сеть остановилась (форка нет)", "—", "—", "—"))
    table(["Сценарий", "Результат", "Раундов в среднем", "Макс. раундов", "Среднее время блока, с"], rows)


def bench_optimizations():
    emit("## 6. Оптимизации: ключ в состоянии и commit по кворуму")
    emit()
    emit(
        f"{TXS_PER_BLOCK} tx в блоке, все счета уже раскрыли ключ (установившийся режим). "
        "Commit «кворум» — минимальный набор подписей с >2/3 силы голоса. Год — без pruning commit."
    )
    emit()
    rows = []
    configs = [
        (HYBRID_ED25519_FALCON_512, HYBRID_ED25519_FALCON_512),
        (HYBRID_ED25519_FALCON_512, HYBRID_ED25519_ML_DSA_44),
        (HYBRID_ED25519_ML_DSA_44, HYBRID_ED25519_ML_DSA_44),
    ]
    for vote_s, tx_s in configs:
        for n in (31, 100, 150):
            base = None
            for key_in_state, mode in [(False, "all"), (True, "all"), (False, "quorum"), (True, "quorum")]:
                _, st = run_heights(n, vote_s, tx_s, key_in_state=key_in_state, commit_mode=mode)
                commit = statistics.mean(x.commit_bytes for x in st)
                block = statistics.mean(x.block_bytes for x in st)
                tx_size = statistics.mean(x.txs_bytes for x in st) / TXS_PER_BLOCK
                base = base or block
                label = {(False, "all"): "без оптимизаций", (True, "all"): "ключ в состоянии",
                         (False, "quorum"): "commit по кворуму", (True, "quorum"): "обе"}[(key_in_state, mode)]
                rows.append(
                    (
                        f"{vote_s.name} / {tx_s.name}",
                        n,
                        label,
                        f"{tx_size:,.0f}",
                        kb(commit),
                        kb(block),
                        f"−{(1 - block / base) * 100:.0f}%" if block < base else "—",
                        gb(block * BLOCKS_PER_DAY * 365),
                        f"{max_tps(tx_size - 4, commit):,.0f}",
                    )
                )
            print(f"  … {vote_s.name}/{tx_s.name}, n={n}", file=sys.stderr)
    table(
        ["Голоса / транзакции", "Валидаторов", "Вариант", "Tx, Б", "Commit, КБ", "Блок, КБ", "Блок vs база", "Год, ГБ", "Макс. TPS"],
        rows,
    )


def main():
    emit("# Модель PQ-консенсуса: результаты замеров")
    emit()
    emit(
        "Все схемы настоящие: Falcon-512 и ML-DSA — liboqs 0.14.0 (AVX2), SLH-DSA — pqcrypto, "
        "Ed25519 — cryptography (OpenSSL)."
    )
    emit()
    bench_signatures()
    bench_tx_sizes()
    results = bench_matrix()
    bench_pruning(results)
    bench_faults()
    bench_optimizations()
    out = pathlib.Path(__file__).parent / "results" / "report.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(out_lines))
    print(f"\nОтчёт: {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
