from supplyguard.popular import PopularIndex
from supplyguard.pypi import PackageInfo
from supplyguard.scoring import assess, closest_popular


def test_ambiguous_match_prefers_better_rank():
    # Both targets are one substitution away with the same technique weight.
    index = PopularIndex.from_rows([("abcd", 1), ("abce", 2)])
    match = closest_popular("abcf", index)
    assert match is not None
    assert match[0] == "abcd"


def test_ambiguous_match_without_ranks_is_alphabetical():
    index = PopularIndex.from_names(["abce", "abcd"])
    first = closest_popular("abcf", index)
    second = closest_popular("abcf", index)
    assert first == second
    assert first[0] == "abcd"


def test_distance_two_without_known_technique_is_ignored():
    # "tabula" -> "tabulate" is two deletions; that alone is not a typo pattern.
    index = PopularIndex.from_names(["tabulate"])
    assert closest_popular("tabula", index) is None


def test_known_popular_name_short_circuits():
    index = PopularIndex.from_rows([("requests", 1)])
    finding = assess("Requests", index, metadata=lambda n: 1 / 0)
    assert finding.level == "OK"
    assert finding.target_rank == 1


def test_metadata_failure_adds_warning_but_does_not_crash():
    index = PopularIndex.from_names(["requests"])
    finding = assess("reqeusts", index, metadata=lambda n: None)
    assert finding.target == "requests"
    assert "PyPI metadata unavailable" in finding.warnings


def test_unregistered_name_is_low_without_similarity_match():
    index = PopularIndex.from_names(["requests"])
    finding = assess("totally-unrelated-name", index,
                     metadata=lambda n: PackageInfo(name=n, exists=False))
    assert finding.level == "LOW"
    assert any("not found on PyPI" in r for r in finding.reasons)


def test_metadata_signals_increase_score():
    index = PopularIndex.from_names(["colorama"])
    fresh = lambda n: PackageInfo(
        name=n, exists=True, first_release="2099-01-01T00:00:00+00:00",
        release_count=1, has_project_url=False, summary="",
    )
    offline = assess("colorma", index)
    online = assess("colorma", index, fresh)
    assert online.score > offline.score
    assert online.level == "HIGH"
