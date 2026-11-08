from supplyguard.parser import parse_requirements
from supplyguard.pypi import PackageInfo
from supplyguard.scoring import assess

POPULAR = frozenset({"requests", "requests-oauthlib", "numpy", "colorama", "boto3", "boto"})


def test_popular_package_is_ok():
    assert assess("requests", POPULAR).level == "OK"
    assert assess("requests-oauthlib", POPULAR).level == "OK"


def test_typosquat_flagged_offline():
    f = assess("reqeusts", POPULAR)
    assert f.target == "requests"
    assert f.level in {"MEDIUM", "HIGH"}


def test_unrelated_name_ok():
    assert assess("flask", POPULAR).level == "OK"


def test_metadata_raises_score():
    fresh = lambda n: PackageInfo(name=n, exists=True, first_release="2099-01-01T00:00:00+00:00",
                                  release_count=1, has_project_url=False, summary="")
    offline = assess("colorma", POPULAR)
    online = assess("colorma", POPULAR, fresh)
    assert online.score > offline.score
    assert online.level == "HIGH"


def test_parse_requirements(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# comment\nrequests>=2.0\nnumpy==1.26 ; python_version>'3.8'\n"
        "-e git+https://example.com/x.git\n--index-url https://pypi.org/simple\n"
        "Requests\ncolorama[extra]  # inline\n"
    )
    assert parse_requirements(req) == ["requests", "numpy", "colorama"]
