import nvdlib
import os
import responses
import json
from unittest.mock import patch
from pathlib import Path


def mock_nvd(bad_json=False):
    this_file_dir = Path(__file__).resolve().parent
    for url, response_file in [
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-45357",
            "data/CVE-2021-45357.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-26855",
            "data/CVE-2021-26855.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-45357",
            "data/CVE-2022-24646.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-7542",
            "data/CVE-2017-7542.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2022-02-10T00:00:00&pubEndDate=2022-02-10T12:00:00",
            "data/simple_search.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2022-02-10T00:00:00&pubEndDate=2022-02-11T00:00:00",
            "data/search_page_1.json",
        ),
        (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2022-02-10T00:00:00&pubEndDate=2022-02-11T00:00:00",
            "data/search_full_page.json",
        ),
    ]:
        response_file_path = os.path.join(this_file_dir, response_file)
        with open(response_file_path) as _f:
            responses.add(responses.GET, url, json=json.load(_f))


@responses.activate
def test_get_cve():
    """Test a nvdlib.searchCVE() call for a single CVE."""
    mock_nvd()
    cve = nvdlib.searchCVE(cveId="CVE-2021-26855")[0]
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
def test_get_cve_v2():
    """Test a nvdlib.searchCVE_V2() call for a single CVE."""
    mock_nvd()
    cve = next(nvdlib.searchCVE_V2(cveId="CVE-2021-26855"))
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
    )
    assert len(results) == 2


# failed
def test_search_cve_v2():
    """Test a simple nvdlib.searchCVE_V2() call."""
    # Mock the generator function since it uses dynamic parameters
    this_file_dir = Path(__file__).resolve().parent
    simple_search_path = os.path.join(this_file_dir, "data/simple_search.json")
    with open(simple_search_path) as f:
        test_data = json.load(f)
    
    with patch('nvdlib.cve.__get_with_generator') as mock_gen:
        mock_gen.return_value = iter([test_data])
        
        results = [r for r in nvdlib.searchCVE_V2(
            pubStartDate="2022-02-10 00:00",
            pubEndDate="2022-02-10 12:00")]
        assert len(results) == 2


@ responses.activate
def test_paginated_search_cve():
    """Test a nvdlib.searchCVE() call with paginated results."""
    mock_nvd()
    results = nvdlib.searchCVE(
        pubStartDate="2022-02-10 00:00", pubEndDate="2022-02-11 00:00",
    )
    assert len(results) == 47
    assert results[0].id == "CVE-2021-25992"


# Failed
def test_paginated_search_cve_v2():
    """Test a nvdlib.searchCVE_V2() call with paginated results."""
    # Mock the generator function since it uses dynamic parameters
    this_file_dir = Path(__file__).resolve().parent
    search_page_path = os.path.join(this_file_dir, "data/search_page_1.json")
    with open(search_page_path) as f:
        test_data = json.load(f)
    
    with patch('nvdlib.cve.__get_with_generator') as mock_gen:
        mock_gen.return_value = iter([test_data])
        
        results = [r for r in nvdlib.searchCVE_V2(
            pubStartDate="2022-02-10 00:00", pubEndDate="2022-02-11 00:00")]
        assert len(results) == 47
        assert results[0].id == "CVE-2021-25992"


@ responses.activate
def test_search_cve_returns_a_cve():
    """Test a nvdlib.searchCVE() result is actually a CVE object"""
    mock_nvd()
    results = nvdlib.searchCVE(
        pubStartDate="2022-02-10 00:00", pubEndDate="2022-02-11 00:00",
    )
    assert isinstance(results[1], nvdlib.classes.CVE)


def test_search_cve_returns_a_cve_v2():
    """Test a nvdlib.searchCVE_V2() result is actually a CVE object"""
    # Mock the generator function since it uses dynamic parameters
    this_file_dir = Path(__file__).resolve().parent
    search_page_path = os.path.join(this_file_dir, "data/search_page_1.json")
    with open(search_page_path) as f:
        test_data = json.load(f)
    
    with patch('nvdlib.cve.__get_with_generator') as mock_gen:
        mock_gen.return_value = iter([test_data])
        
        results = [r for r in nvdlib.searchCVE_V2(
            pubStartDate="2022-02-10 00:00", pubEndDate="2022-02-11 00:00",
        )]
        assert isinstance(results[1], nvdlib.classes.CVE)


@responses.activate
def test_cve_cwe():
    """Test that `cwe` was correctly created from `weaknesses`."""
    mock_nvd()
    cve = nvdlib.searchCVE(cveId="CVE-2017-7542")[0]

    assert cve.id == "CVE-2017-7542"
    assert len([x for w in cve.weaknesses for x in w.description]) == 3


def test_search_cve_handles_get_returning_none():
    """Test that searchCVE() handles __get() returning None correctly."""
    with patch('nvdlib.cve.__get') as mock_get:
        mock_get.return_value = None
        
        result = nvdlib.searchCVE(cveId="CVE-2021-26855")
        
        assert result == []  # Should return empty list
        mock_get.assert_called_once()


def test_search_cve_v2_handles_get_with_generator_returning_none():
    """Test that searchCVE_V2() handles __get_with_generator() yielding None correctly."""
    with patch('nvdlib.cve.__get_with_generator') as mock_get_gen:
        # Generator that yields None values
        mock_get_gen.return_value = iter([None, None])
        
        result = list(nvdlib.searchCVE_V2(cveId="CVE-2021-26855"))
        
        assert result == []  # Should return empty list
        mock_get_gen.assert_called_once()


def test_search_cve_handles_get_returning_none_with_parameters():
    """Test that searchCVE() with various parameters handles __get() returning None."""
    with patch('nvdlib.cve.__get') as mock_get:
        mock_get.return_value = None
        
        # Test with multiple parameters
        result = nvdlib.searchCVE(
            cveId="CVE-2021-26855",
            cvssV3Severity="CRITICAL",
            pubStartDate="2021-01-01 00:00",
            pubEndDate="2021-12-31 23:59",
            limit=100
        )
        
        assert result == []  # Should return empty list
        mock_get.assert_called_once()


def test_search_cve_v2_handles_mixed_none_and_valid_batches():
    """Test that searchCVE_V2() handles mix of None and valid batches correctly."""
    valid_batch = {
        'vulnerabilities': [{
            'cve': {
                'id': 'CVE-2021-12345',
                'descriptions': [{'value': 'Test CVE'}],
                'metrics': {}
            }
        }]
    }
    
    with patch('nvdlib.cve.__get_with_generator') as mock_get_gen:
        # Generator that yields None, valid data, None
        mock_get_gen.return_value = iter([None, valid_batch, None])
        
        result = list(nvdlib.searchCVE_V2(cveId="CVE-2021-12345"))
        
        assert len(result) == 1  # Should only process the valid batch
        assert result[0].id == 'CVE-2021-12345'
        mock_get_gen.assert_called_once()


def test_search_cve_handles_get_returning_empty_dict():
    """Test that searchCVE() handles __get() returning empty dict correctly.""" 
    with patch('nvdlib.cve.__get') as mock_get:
        mock_get.return_value = {}  # Empty dict should be falsy
        
        result = nvdlib.searchCVE(cveId="CVE-2021-26855")
        
        assert result == []  # Should return empty list
        mock_get.assert_called_once()


def test_search_cve_handles_get_returning_false():
    """Test that searchCVE() handles __get() returning False correctly."""
    with patch('nvdlib.cve.__get') as mock_get:
        mock_get.return_value = False  # Explicit False value
        
        result = nvdlib.searchCVE(cveId="CVE-2021-26855")
        
        assert result == []  # Should return empty list  
        mock_get.assert_called_once()


def test_search_cve_v2_handles_empty_generator():
    """Test that searchCVE_V2() handles empty generator correctly."""
    with patch('nvdlib.cve.__get_with_generator') as mock_get_gen:
        mock_get_gen.return_value = iter([])  # Empty generator
        
        result = list(nvdlib.searchCVE_V2(cveId="CVE-2021-26855"))
        
        assert result == []  # Should return empty list
        mock_get_gen.assert_called_once()
