from unittest.mock import patch

import nvdlib


def test_search_cve_history_unwraps_change():
    """Test that searchCVEHistory returns each inner `change` record, as an object or as a dict."""
    payload = {
        'cveChanges': [
            {'change': {'cveId': 'CVE-2021-44228', 'eventName': 'Initial Analysis', 'details': []}}
        ]
    }
    with patch('nvdlib.history.__get') as mock_get:
        mock_get.return_value = payload
        result = nvdlib.searchCVEHistory(cveId='CVE-2021-44228')
        assert isinstance(result[0], nvdlib.classes.CVEHistory)
        assert result[0].eventName == 'Initial Analysis'

        result = nvdlib.searchCVEHistory(cveId='CVE-2021-44228', asDict=True)
        assert result[0] == payload['cveChanges'][0]['change']
