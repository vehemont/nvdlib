import nvdlib
import responses
import json


def mock_nvd():
    for url, response_file in [
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-45357",
            "tests/data/CVE-2021-45357.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-26855",
            "tests/data/CVE-2021-26855.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-45357",
            "tests/data/CVE-2022-24646.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2022-02-10T00:00:00&pubEndDate=2022-02-10T12:00:00",
            "tests/data/simple_search.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2022-02-10T00:00:00&pubEndDate=2022-02-11T00:00:00",
            "tests/data/search_page_1.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2022-02-10T00:00:00&pubEndDate=2022-02-11T00:00:00",
            "tests/data/search_full_page.json",
        ),
    ]:
        with open(response_file) as _f:
            responses.add(responses.GET, url, json=json.load(_f))


@responses.activate
def test_get_cve():
    """Test a nvdlib.searchCVE() call for a single CVE."""
    mock_nvd()
    cve = nvdlib.searchCVE(cveId="CVE-2021-26855", verbose=True)[0]
    assert cve.id == "CVE-2021-26855"
    assert cve.v2severity == "HIGH"
    assert cve.v2exploitability == 10.0
    assert cve.v2impactScore == 6.4
    assert cve.score == ['V31', 9.8, 'CRITICAL']
    assert (
        cve.descriptions[0].value
        == "Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078."
    )
    assert cve.v31vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@responses.activate
def test_search_cve():
    """Test a simple nvdlib.searchCVE() call."""
    mock_nvd()
    results = nvdlib.searchCVE(
        pubStartDate="2022-02-10 00:00",
        pubEndDate="2022-02-10 12:00",
        verbose=True,
    )
    assert len(results) == 2


@responses.activate
def test_paginated_search_cve():
    """Test a nvdlib.searchCVE() call with paginated results."""
    mock_nvd()
    results = nvdlib.searchCVE(
        pubStartDate="2022-02-10 00:00", pubEndDate="2022-02-11 00:00",
        verbose=True
    )
    assert len(results) == 47
    assert results[0].id == "CVE-2021-25992"


@responses.activate
def test_search_cve_returns_a_cve():
    """Test a nvdlib.searchCVE() result is actually a CVE object"""
    mock_nvd()
    results = nvdlib.searchCVE(
        pubStartDate="2022-02-10 00:00", pubEndDate="2022-02-11 00:00",
        verbose=True
    )
    assert isinstance(results[1], nvdlib.classes.CVE)
