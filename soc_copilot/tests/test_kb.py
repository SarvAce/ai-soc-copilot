"""Tests for the knowledge base (spec Table 19, WP1 "Done when")."""

from __future__ import annotations

import ipaddress

import pytest

from soc_copilot.kb.loader import (
    KB_FILES, get_kb, kb_hash, load_kb, lookup_country, lookup_threat_intel, lookup_zone,
)


@pytest.fixture(scope="module")
def kb():
    """The loaded knowledge base."""
    return get_kb()


def test_every_table_19_file_is_present(kb):
    """Table 19 lists eleven files; loader.py covers the ten it reads plus the derived baseline."""
    assert len(KB_FILES) == 10          # the eleventh, the baseline, is derived in core/baseline.py
    assert kb.identities and kb.threat_intel and kb.zones and kb.geoip
    assert kb.detection_rules and kb.evidence_requirements
    assert kb.playbooks and kb.attack_mapping and kb.priority_matrix


def test_population_matches_the_spec(kb):
    """25 users: 3 administrators, 2 service accounts and 20 staff (spec §12.3)."""
    roles = [row["role"] for row in kb.identities.values()]
    assert len(kb.identities) == 25
    assert roles.count("administrator") == 3
    assert roles.count("service") == 2
    assert roles.count("staff") == 20
    assert len({row["timezone"] for row in kb.identities.values()}) == 2


def test_kb_hash_is_stable(tmp_path):
    """The same files always hash to the same value, so a result can name its KB version."""
    assert kb_hash() == kb_hash()
    assert len(kb_hash()) == 12


def test_only_documentation_and_private_addresses_appear(kb):
    """Spec §12.3 permits only documentation and private ranges."""
    allowed = [ipaddress.ip_network(cidr) for cidr in
               ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    for row in kb.zones + kb.geoip:
        network = ipaddress.ip_network(row["cidr"], strict=False)
        assert any(network.subnet_of(block) for block in allowed  # type: ignore[arg-type]
                   if block.version == network.version), row


def test_zone_lookup_prefers_the_longest_prefix(kb):
    """Guest Wi-Fi inside 10/8 must beat the corporate LAN row."""
    assert lookup_zone(kb, "10.0.1.10")["zone"] == "corporate_lan"
    assert lookup_zone(kb, "10.50.0.5")["zone"] == "guest_wifi"
    assert lookup_zone(kb, "198.51.100.10")["shared_egress"] is True
    assert lookup_zone(kb, "10.0.1.10")["shared_egress"] is False


def test_threat_intel_matches_addresses_and_cidrs(kb):
    """T4 must match a bare address and a CIDR, and miss everything else."""
    assert lookup_threat_intel(kb, "203.0.113.7")["label"] == "brute_force_source"
    assert lookup_threat_intel(kb, "203.0.113.201") is not None     # inside 203.0.113.200/29
    # The spray sources of S2, S3 and S8 must NOT match, or their disposition changes.
    for ip in ("203.0.113.50", "203.0.113.60", "203.0.113.90", "203.0.113.55"):
        assert lookup_threat_intel(kb, ip) is None
    assert lookup_threat_intel(kb, "not-an-ip") is None


def test_country_lookup(kb):
    """The attacker range and the corporate range must be different countries."""
    assert lookup_country(kb, "10.0.1.10") == "NL"
    assert lookup_country(kb, "198.51.100.10") == "NL"
    assert lookup_country(kb, "203.0.113.7") == "SG"
    assert lookup_country(kb, "2001:db8::1") == "DE"


def test_the_s2_and_s11_sources_are_not_a_new_country(kb):
    """The deck states S2 fires Table 28 row 4: no TI match, persistence, new country
    or benign explanation. A source in a country bob has never used would add a
    malicious indicator and fire row 2 instead (DEVIATIONS D19)."""
    for ip in ("203.0.113.50", "203.0.113.55", "203.0.113.56"):
        assert lookup_country(kb, ip) == "NL", ip
    # S1 stays a new country, which reinforces its row 2.
    assert lookup_country(kb, "203.0.113.7") == "SG"


def test_playbook_steps_are_well_formed(kb):
    """Every step needs an ID, a type and an approval flag (check R8)."""
    steps = kb.playbooks["steps"]
    ids = [step["step_id"] for step in steps]
    assert len(ids) == len(set(ids)), "step IDs must be unique"
    for step in steps:
        assert step["type"] in ("investigate", "contain", "communicate")
        assert isinstance(step["requires_approval"], bool)
        # Spec SOC-PoC-008: anything that would change a system needs approval.
        if step["type"] == "contain":
            assert step["requires_approval"] is True, step["step_id"]
    assert "PB-ATO-02" in ids and "PB-SPR-01" in ids


def test_attack_mapping_dropped_t1204_and_added_subtechniques(kb):
    """Audit finding L11: T1204 was mapped without evidence and must be gone."""
    techniques = kb.attack_mapping["techniques"]
    all_ids = [technique["id"] for group in techniques.values() for technique in group]
    assert "T1204" not in all_ids
    assert "T1110.001" in all_ids and "T1110.003" in all_ids
    # R9: these two may only be cited when their required fact exists.
    ato = {technique["id"]: technique["requires_fact"] for technique in techniques["ATO"]}
    assert ato["T1078"] == "success_after_failures"
    assert ato["T1098.005"] == "mfa_device_registered"


def test_evidence_requirements_cover_every_hypothesis(kb):
    """The Planner needs a checklist for GUESS, SPRAY and ATO (spec Table 26)."""
    hypotheses = kb.evidence_requirements["hypotheses"]
    assert set(hypotheses) == {"GUESS", "SPRAY", "ATO"}
    for name, block in hypotheses.items():
        for item in block["items"]:
            assert item["item"].startswith(name + ".")
            assert item["scope"] in ("account", "case")
            assert item["tools"], item


def test_spray_first_pass_tools_match_figure_4(kb):
    """Figure 4 shows pass 1 of S2 planning T1, T2, T4, T5, T8, T9 and T10."""
    items = kb.evidence_requirements["hypotheses"]["SPRAY"]["items"]
    tools = sorted({item["tools"][0] for item in items}, key=lambda name: int(name[1:]))
    assert tools == ["T1", "T2", "T4", "T5", "T8", "T9", "T10"]


def test_ato_adds_exactly_t3_t6_t7_over_spray(kb):
    """Figure 4 shows pass 2 of S2 planning T3, T6 and T7 for bob."""
    requirements = kb.evidence_requirements["hypotheses"]
    spray_tools = {item["tools"][0] for item in requirements["SPRAY"]["items"]}
    ato_tools = {item["tools"][0] for item in requirements["ATO"]["items"]}
    assert ato_tools - spray_tools == {"T3", "T6", "T7"}


def test_priority_matrix_matches_table_29(kb):
    """Every cell of Table 29, read straight from the file."""
    matrix = kb.priority_matrix["matrix"]
    assert matrix["SUSPECTED_COMPROMISE"] == {"HIGH": "P1", "NORMAL": "P2"}
    assert matrix["UNRESOLVED_SUCCESS_NOT_RULED_OUT"] == {"HIGH": "P1", "NORMAL": "P2"}
    assert matrix["UNRESOLVED_SUCCESS_RULED_OUT"] == {"HIGH": "P3", "NORMAL": "P3"}
    assert matrix["ATTACK_ATTEMPT_NO_ACCESS"] == {"HIGH": "P2", "NORMAL": "P3"}
    assert matrix["LIKELY_BENIGN"] == {"HIGH": "P3", "NORMAL": "P4"}


def test_disposition_rows_are_in_table_28_order(kb):
    """Row 2 must come before row 3, or a malicious case could read as benign."""
    rows = kb.priority_matrix["disposition_rows"]
    assert [row["row"] for row in rows] == [1, 2, 3, 4, 5, 6]
    assert rows[1]["disposition"] == "SUSPECTED_COMPROMISE"
    assert rows[2]["disposition"] == "LIKELY_BENIGN"


def test_identity_helpers(kb):
    """is_known_user and is_privileged back checks R3 and the impact rule."""
    assert kb.is_known_user("alice@corp.example")
    assert not kb.is_known_user("ghost1@corp.example")
    assert kb.is_privileged("uma.admin@corp.example")
    assert not kb.is_privileged("bob@corp.example")


def test_load_kb_is_independent_of_the_cache(kb):
    """load_kb reads from disk every time, which the tests rely on."""
    fresh = load_kb()
    assert fresh.kb_hash == kb.kb_hash
    assert fresh.identities.keys() == kb.identities.keys()
