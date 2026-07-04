"""main.py — NetErrror Wallet Scanner — Fixed for Windows multiprocessing

Передача разделяемых объектов как аргументы в дочерние процессы.
"""

import json
import os
import sys
import threading
import time
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from datetime import datetime

from bip39 import generate_mnemonic, mnemonic_to_seed
from bitcoin_keys import seed_to_master_key, private_key_to_address as btc_address
from ethereum_keys import private_key_to_address as eth_address
from api_client import ApiClient

# ─── Конфиг ──────────────────────────────────────────────────────────────────
PROCESSES = multiprocessing.cpu_count()
THREADS_PER_PROCESS = 25
TOTAL_THREADS = PROCESSES * THREADS_PER_PROCESS

BTC_API = "https://blockchain.info/balance?active={address}"
ETH_API = "https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest"
TIMEOUT = 2
RETRIES = 0
OUTPUT_FILE = "found_wallets.json"
BATCH_SIZE = 50


def save_results(wallets_list):
    """Сохраняет найденные кошельки в файл."""
    with open(OUTPUT_FILE, "w") as f:
        json.dump(list(wallets_list), f, indent=2)


def generate_batch(size: int) -> list:
    return [generate_mnemonic(12) for _ in range(size)]


def check_btc_balance(client: ApiClient, address: str) -> int:
    try:
        url = BTC_API.replace("{address}", address)
        data = client.get(url)
        return int(data.get(address, {}).get("final_balance", 0))
    except:
        return -1


def check_eth_balance(client: ApiClient, address: str) -> int:
    try:
        url = ETH_API.replace("{address}", address)
        data = client.get(url)
        if data.get("status") == "1":
            return int(data.get("result", 0))
        return 0
    except:
        return -1


def process_single(mnemonic: str, client: ApiClient) -> dict | None:
    try:
        seed = mnemonic_to_seed(mnemonic)
        priv_key = seed_to_master_key(seed)
        btc_addr = btc_address(priv_key, compressed=True)
        eth_addr = eth_address(priv_key)

        btc_bal = check_btc_balance(client, btc_addr)
        eth_bal = check_eth_balance(client, eth_addr)

        if btc_bal > 0 or eth_bal > 0:
            return {
                "mnemonic": mnemonic,
                "btc_address": btc_addr,
                "btc_balance_satoshi": btc_bal if btc_bal > 0 else 0,
                "eth_address": eth_addr,
                "eth_balance_wei": eth_bal if eth_bal > 0 else 0,
                "found_at": datetime.now().isoformat(),
            }
    except:
        pass
    return None


def worker_process(process_id: int, stats_dict, lock, wallets_list):
    """Рабочий процесс, принимает разделяемые объекты напрямую."""
    local_checked = 0

    with ThreadPoolExecutor(max_workers=THREADS_PER_PROCESS) as executor:
        clients = [ApiClient(timeout=TIMEOUT, retries=RETRIES)
                   for _ in range(THREADS_PER_PROCESS)]

        while True:
            mnemonics = generate_batch(BATCH_SIZE)

            futures = []
            for i, mnemonic in enumerate(mnemonics):
                client = clients[i % len(clients)]
                future = executor.submit(process_single, mnemonic, client)
                futures.append(future)

            for future in as_completed(futures):
                result = future.result()
                local_checked += 1

                with lock:
                    stats_dict["checked"] += 1
                    total = stats_dict["checked"]
                    btc_found = stats_dict["btc_nonzero"]
                    eth_found = stats_dict["eth_nonzero"]

                if result:
                    if result["btc_balance_satoshi"] > 0:
                        with lock:
                            stats_dict["btc_nonzero"] += 1
                    if result["eth_balance_wei"] > 0:
                        with lock:
                            stats_dict["eth_nonzero"] += 1
                    wallets_list.append(result)
                    save_results(wallets_list)
                    sys.stdout.write(
                        f"\n[!!!] НАЙДЕН КОШЕЛЁК!!! {result['mnemonic'][:40]}...\n"
                    )
                    sys.stdout.flush()

                if local_checked % 10 == 0:
                    elapsed = (datetime.now() - datetime.fromisoformat(
                        stats_dict["started"]
                    )).total_seconds()
                    rate = total / elapsed if elapsed > 0 else 0
                    sys.stdout.write(
                        f"\r[P{process_id:02d}] #{total:8d} | "
                        f"Rate: {rate:.1f}/s | "
                        f"BTC: {btc_found} | ETH: {eth_found} | "
                        f"Saved: {len(wallets_list)}"
                    )
                    sys.stdout.flush()


def main():
    print("=" * 60)
    print("  NetErrror Wallet Scanner")
    print("=" * 60)
    print(f"  Процессов: {PROCESSES}")
    print(f"  Потоков на процесс: {THREADS_PER_PROCESS}")
    print(f"  Всего потоков: {TOTAL_THREADS}")
    print(f"  Таймаут: {TIMEOUT}с")
    print(f"  Batch size: {BATCH_SIZE}")
    print(f"  Вывод: {OUTPUT_FILE}")
    print(f"  Ctrl+C для остановки")
    print("=" * 60)

    # Создаём разделяемые объекты
    manager = multiprocessing.Manager()
    stats = manager.dict({
        "checked": 0,
        "btc_nonzero": 0,
        "eth_nonzero": 0,
        "started": datetime.now().isoformat(),
    })
    stats_lock = manager.Lock()
    found_wallets = manager.list()

    # Загружаем старые находки
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r") as f:
                old = json.load(f)
                for w in old:
                    if w not in found_wallets:
                        found_wallets.append(w)
            print(f"[*] Загружено {len(old)} ранее найденных кошельков")
        except:
            pass

    with ProcessPoolExecutor(max_workers=PROCESSES) as executor:
        futures = []
        for i in range(PROCESSES):
            fut = executor.submit(worker_process, i, stats, stats_lock, found_wallets)
            futures.append(fut)

        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            print("\n\n[*] Остановка...")
            save_results(found_wallets)
            with stats_lock:
                total = stats["checked"]
                btc_found = stats["btc_nonzero"]
                eth_found = stats["eth_nonzero"]
            print(f"[*] Всего проверено: {total}")
            print(f"[*] BTC с балансом: {btc_found}")
            print(f"[*] ETH с балансом: {eth_found}")
            print(f"[*] Сохранено: {len(found_wallets)}")
            sys.exit(0)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()