from unittest.mock import patch

import nvdlib


def test_search_source_returns_sources():
    """Test that searchSource returns each `sources` record, as an object or as a dict."""
    payload = {
        'sources': [
            {'name': 'MITRE', 'contactEmail': 'cve@mitre.org', 'sourceIdentifiers': ['cve@mitre.org']}
        ]
    }
    with patch('nvdlib.source.__get') as mock_get:
        mock_get.return_value = payload
        result = nvdlib.searchSource(sourceIdentifier='cve@mitre.org')
        assert isinstance(result[0], nvdlib.classes.Source)
        assert result[0].name == 'MITRE'

        result = nvdlib.searchSource(sourceIdentifier='cve@mitre.org', asDict=True)
        assert result[0] == payload['sources'][0]
