from vaultbreaker.cli import MODULE_MAP
def test_all_modules(): assert set(MODULE_MAP.keys()) == {"sqli","mongo","redis","elastic","cred","exfil"}
