def test_load_all_registers_many_and_is_idempotent():
    from pepperspray.core.registry import REGISTRY
    from pepperspray.tools import load_all

    load_all()
    n = len(REGISTRY.all())
    assert n >= 100  # full parity across families
    load_all()  # idempotent: no duplicate-registration error
    assert len(REGISTRY.all()) == n
    fams = set(REGISTRY.families())
    assert {"recon", "web", "exploitation", "binary", "cloud", "forensics", "cve"} <= fams
