from pepperspray.core.cache import ResultCache


def test_cache_key_stable_and_get_set():
    c = ResultCache(maxsize=10, ttl=100)
    k1 = c.key("nmap", {"target": "a", "ports": "80"})
    k2 = c.key("nmap", {"ports": "80", "target": "a"})
    assert k1 == k2  # order-independent
    assert c.get(k1) is None
    c.set(k1, {"v": 1})
    assert c.get(k1) == {"v": 1}
