import urllib.parse

import pytest

from nvdlib.classes import __convert
from nvdlib.cve import __buildCVECall


def _cve(metrics):
    return __convert('cve', {'id': 'CVE-2024-0001', 'metrics': metrics})


def test_primary_v40_score_is_used_when_not_first():
    cve = _cve({
        'cvssMetricV40': [
            {
                'type': 'Secondary',
                'cvssData': {
                    'version': '4.0',
                    'vectorString': 'CVSS:4.0/AV:N',
                    'baseScore': 5.3,
                    'baseSeverity': 'MEDIUM',
                    'exploitMaturity': 'NOT_DEFINED',
                },
            },
            {
                'type': 'Primary',
                'cvssData': {
                    'version': '4.0',
                    'vectorString': 'CVSS:4.0/AV:N/AT:N',
                    'baseScore': 8.7,
                    'baseSeverity': 'HIGH',
                    'attackVector': 'NETWORK',
                    'Safety': 'NOT_DEFINED',
                },
            },
        ]
    })

    assert cve.score == ['V40', 8.7, 'HIGH']
    assert cve.v40score == 8.7
    assert cve.v40vector == 'CVSS:4.0/AV:N/AT:N'
    assert cve.v40severity == 'HIGH'
    assert cve.v40attackVector == 'NETWORK'
    assert cve.v40Safety == 'NOT_DEFINED'
    assert not hasattr(cve, 'v40exploitMaturity')
    assert not hasattr(cve, 'v40threatScore')


def test_missing_threat_score_does_not_raise_and_not_defined_is_copied():
    cve = _cve({
        'cvssMetricV40': [
            {
                'type': 'Secondary',
                'cvssData': {
                    'version': '4.0',
                    'vectorString': 'CVSS:4.0/AV:N',
                    'baseScore': 9.5,
                    'baseSeverity': 'CRITICAL',
                    'exploitMaturity': 'NOT_DEFINED',
                },
            }
        ],
        'cvssMetricV31': [
            {
                'type': 'Primary',
                'cvssData': {
                    'version': '3.1',
                    'vectorString': 'CVSS:3.1/AV:N',
                    'baseScore': 9.8,
                    'baseSeverity': 'CRITICAL',
                    'attackVector': 'NETWORK',
                    'attackComplexity': 'LOW',
                    'privilegesRequired': 'NONE',
                    'userInteraction': 'NONE',
                    'scope': 'UNCHANGED',
                    'confidentialityImpact': 'HIGH',
                    'integrityImpact': 'HIGH',
                    'availabilityImpact': 'HIGH',
                },
                'exploitabilityScore': 3.9,
                'impactScore': 5.9,
            }
        ],
    })

    assert cve.score == ['V40', 9.5, 'CRITICAL']
    assert cve.v40exploitMaturity == 'NOT_DEFINED'
    assert not hasattr(cve, 'v40threatScore')
    assert not hasattr(cve, 'v40environmentalScore')


def _v31(metric_type, score, severity):
    return {
        'type': metric_type,
        'cvssData': {
            'version': '3.1',
            'vectorString': 'CVSS:3.1/AV:N',
            'baseScore': score,
            'baseSeverity': severity,
            'attackVector': 'NETWORK',
            'attackComplexity': 'LOW',
            'privilegesRequired': 'NONE',
            'userInteraction': 'NONE',
            'scope': 'UNCHANGED',
            'confidentialityImpact': 'HIGH',
            'integrityImpact': 'HIGH',
            'availabilityImpact': 'HIGH',
        },
        'exploitabilityScore': 3.9,
        'impactScore': 5.9,
    }


def test_primary_v31_score_is_used_when_not_first():
    cve = _cve({
        'cvssMetricV31': [
            _v31('Secondary', 5.0, 'MEDIUM'),
            _v31('Primary', 9.8, 'CRITICAL'),
        ]
    })

    assert cve.score == ['V31', 9.8, 'CRITICAL']
    assert cve.v31score == 9.8
    assert cve.v31exploitability == 3.9


def test_cvss_v4_search_parameters():
    parameters, _ = __buildCVECall(
        cvssV4Severity='high',
        cvssV4Metrics='AV:N/AT:N',
        cvssV3Severity='HIGH',
    )

    assert parameters['cvssV4Severity'] == 'HIGH'
    assert parameters['cvssV4Metrics'] == urllib.parse.quote_plus('AV:N/AT:N', encoding='utf-8')
    assert parameters['cvssV3Severity'] == 'HIGH'


def test_cvss_v4_severity_rejects_none():
    with pytest.raises(SyntaxError):
        __buildCVECall(cvssV4Severity='NONE')
