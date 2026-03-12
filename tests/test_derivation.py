import pytest
import csv

import crypto


def seed_to_bytes(seed: int):
    return seed.to_bytes(17, byteorder="big")


# seed mnemonic:
# spice rapid hub ten face funny boil hope future rhythm scheme movie
SEED_INT = 4457419962331937427314377610565619035271
SEED = seed_to_bytes(SEED_INT)


def load_test_data():
    with open("tests/tests_data.csv", newline="", encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return [
            (int(row["seed"]), row["passphrase"], row["service"], row["year"], row["quarter"], row["mode"], row["password"])
            for row in reader
        ]


def test_simple():
    seed = SEED_INT
    passphrase = 'qwerty'
    service = 'yahoomail'
    year = '2026'
    quarter = '1'
    mode = 'STRONG'

    should_result = '8JtjfMGoCJpwaXnNrCQ4Ww--'

    fact_result = crypto.generate_password(
        seed=seed,
        passphrase=passphrase,
        service=service,
        year=year,
        quarter=quarter,
        mode=mode
    )

    assert fact_result == should_result


def test_empty():
    seed = SEED_INT
    passphrase = ''
    service = ''
    year = ''
    quarter = ''
    mode = 'STRONG'

    should_result = 'do2ohZKfpN4*FMEMk2mAwA--'

    fact_result = crypto.generate_password(
        seed=seed,
        passphrase=passphrase,
        service=service,
        year=year,
        quarter=quarter,
        mode=mode
    )

    assert fact_result == should_result


def test_ultra():
    seed = SEED_INT
    passphrase = 'qwerty'
    service = 'yahoomail'
    year = '2026'
    quarter = '1'
    mode = 'ULTRA'
    should_result = '79qVCnqeFBIoqsNevcgJzPWxkmV1PT5pejbV_OXX2D1A8o89tVS0xAYdn6*UXW1p3pp_AKDaZFvvfdxyOEwa*cjwkJhmGcBRa88HOW4KHynicVB5QkM*hQ--'

    fact_result = crypto.generate_password(
        seed=seed,
        passphrase=passphrase,
        service=service,
        year=year,
        quarter=quarter,
        mode=mode
    )

    assert fact_result == should_result


def test_zero_seed():
    # seed: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about [0,0,0,0,0,0,0,0,0,0,0,3]
    seed = 3
    passphrase = 'qwerty'
    service = 'yahoomail'
    year = '2026'
    quarter = '1'
    mode = 'STRONG'

    should_result = '1lGD7kiYenIoRkmz5mr2vA--'

    fact_result = crypto.generate_password(
        seed=seed,
        passphrase=passphrase,
        service=service,
        year=year,
        quarter=quarter,
        mode=mode
    )

    assert fact_result == should_result


def test_unicode():
    seed = SEED_INT
    passphrase = '🍎ΝЯ个ÓÿК🍕Δыq😎ل'
    service = 'yahoomail'
    year = '2026'
    quarter = '1'
    mode = 'STRONG'

    should_result = '7txBXbHjOZFR3DfgdkwuTQ--'

    fact_result = crypto.generate_password(
        seed=seed,
        passphrase=passphrase,
        service=service,
        year=year,
        quarter=quarter,
        mode=mode
    )

    assert fact_result == should_result


@pytest.mark.parametrize('seed,passphrase,service,year,quarter,mode,should_result', load_test_data())
def test_derivations(seed,passphrase,service,year,quarter,mode,should_result):
    fact_result = crypto.generate_password(
        seed=seed,
        passphrase=passphrase,
        service=service,
        year=year,
        quarter=quarter,
        mode=mode,
        iterations_override=10
    )

    assert fact_result == should_result