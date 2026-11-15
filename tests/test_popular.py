from supplyguard.popular import PopularIndex, load_popular


def test_from_rows_normalizes_and_ranks():
    index = PopularIndex.from_rows([("Python_DateUtil", 100), ("requests", 200)])
    assert "python-dateutil" in index
    assert index.rank["python-dateutil"] == 1
    assert index.rank["requests"] == 2
    assert index.downloads["requests"] == 200
    assert len(index) == 2


def test_duplicate_rows_keep_first_rank():
    index = PopularIndex.from_rows([("a", 1), ("a", 2), ("b", 3)])
    assert len(index) == 2
    assert index.downloads["a"] == 1


def test_indexes_are_built():
    index = PopularIndex.from_names(["pyyaml", "requests"])
    assert "pyyaml" in index.by_stripped["pyyaml"]
    assert "requests" in index.by_length[8]
    assert index.rank["requests"] == 0


def test_load_popular_behaves_like_a_set():
    popular = load_popular()
    assert len(popular) >= 10000
    assert "requests" in popular
    assert "definitely-not-a-real-package-xyz" not in popular
    assert isinstance(list(popular)[0], str)


def test_load_popular_custom_file(tmp_path):
    path = tmp_path / "popular.txt"
    path.write_text("# source: test\nboto3\t42\nnumpy\n", encoding="utf-8")
    popular = load_popular(path)
    assert popular.downloads["boto3"] == 42
    assert popular.rank["boto3"] == 1
    assert popular.rank["numpy"] == 2
