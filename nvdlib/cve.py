import urllib.parse

from typing import Generator, Optional, Union, List, Tuple, Any, Dict
from datetime import datetime
from .classes import __convert, CVE
from .get import __get, __get_with_generator


def searchCVE(
        cpeName: Optional[str] = None,
        cveId: Optional[str] = None,
        cvssV2Metrics: Optional[str] = None,
        cvssV2Severity: Optional[str] = None,
        cvssV3Metrics: Optional[str] = None,
        cvssV3Severity: Optional[str] = None,
        cweId: Optional[str] = None,
        hasCertAlerts: Optional[bool] = None,
        hasCertNotes: Optional[bool] = None,
        hasKev: Optional[bool] = None,
        hasOval: Optional[bool] = None,
        isVulnerable: Optional[bool] = None,
        keywordExactMatch: Optional[bool] = None,
        keywordSearch: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        noRejected: Optional[bool] = None,
        pubStartDate: Optional[Union[str, datetime]] = None,
        pubEndDate: Optional[Union[str, datetime]] = None,
        sourceIdentifier: Optional[str] = None,
        versionEnd: Optional[str] = None,
        versionEndType: Optional[str] = None,
        versionStart: Optional[str] = None,
        versionStartType: Optional[str] = None,
        virtualMatchString: Optional[str] = None,
        limit: Optional[int] = None,
        delay: Optional[float] = None,
        key: Optional[str] = None,
        verbose: Optional[bool] = None
) -> List[CVE]:
    """Build and send GET request then return list of objects containing a collection of CVEs. For more information on the parameters available, please visit https://nvd.nist.gov/developers/vulnerabilities 

    :param cpeName: This value will be compared agains the CPE Match Criteria within a CVE applicability statement. (i.e. find the vulnerabilities attached to that CPE). Partial match strings are allowed.
    :type cpeName: str

    :param cveId: Returns a single CVE that already exists in the NVD.
    :type cveId: str

    :param cvssV2Metrics: This parameter returns only the CVEs that match the provided CVSSv2 vector string. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV3Metrics.
    :type cvssV2Metrics: str

    :param cvssV2Severity: Find vulnerabilities having a 'LOW', 'MEDIUM', or 'HIGH' version 2 severity.
    :type cvssV2Severity: str

    :param cvssV3Metrics: This parameter returns only the CVEs that match the provided CVSSv3 vector string. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV2Metrics.
    :type cvssV3Metrics: str

    :param cvssV3Severity: Find vulnerabilities having a 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL' version 3 severity.
    :type cvssV3Severity: str

    :param cweId: Filter collection by CWE (Common Weakness Enumeration) ID. You can find a list at https://cwe.mitre.org/. A CVE can have multiple CWE IDs assigned to it.
    :type cweId: str

    :param hasCertAlerts: Returns CVE that contain a Technical Alert from US-CERT.
    :type hasCertAlerts: bool

    :param hasCertNotes: Returns CVE that contain a Vulnerability Note from CERT/CC.
    :type hasCertNotes: bool

    :param hasKev: Returns CVE that appear in CISAs Known Exploited Vulnerabilities (KEV) catalog.
    :type hasKev: bool

    :param hasOval: Returns CVE that contain information from MITRE's Open Vulnerability and Assessment Language (OVAL) before this transitioned to the Center for Internet Security (CIS).
    :type hasOval: bool

    :param isVulnerable: Returns CVE associated with a specific CPE, where the CPE is also considered vulnerable. **REQUIRES** `cpeName` parameter. `isVulnerable` is not compatible with `virtualMatchString` parameter.
    :type isVulnerable: bool    

    :param keywordExactMatch: When `keywordSearch` is used along with `keywordExactmatch`, it will search the NVD for CVEs containing exactly what was passed to `keywordSearch`. **REQUIRES** `keywordSearch`.
    :type keywordExactMatch: bool

    :param keywordSearch: Searches CVEs where a word or phrase is found in the current description. If passing multiple keywords with a space character in between then each word must exist somewhere in the description, not necessarily together unless `keywordExactMatch=True` is passed to `searchCVE`.
    :type keywordSearch: str

    :param lastModStartDate: These parameters return only the CVEs that were last modified during the specified period. If a CVE has been modified more recently than the specified period, it will not be included in the response. If filtering by the last modified date, both `lastModStartDate` and `lastModEndDate` are REQUIRED. The maximum allowable range when using any date range parameters is 120 consecutive days.
    :type lastModStartDate: str,datetime obj

    :param lastModEndDate: Required if using lastModStartDate.
    :type lastModEndDate: str, datetime obj

    :param noRejected: Filters out all CVEs that are in a reject or rejected status. Searches without this parameter include rejected CVEs.
    :type noRejected: bool

    :param pubStartDate: These parameters return only the CVEs that were added to the NVD (i.e., published) during the specified period. If filtering by the published date, both `pubStartDate` and `pubEndDate` are REQUIRED. The maximum allowable range when using any date range parameters is 120 consecutive days.
    :type pubStartDate: str,datetime obj

    :param pubEndDate: Required if using pubStartDate.
    :type pubEndDate: str, datetime obj

    :param sourceIdentifier: Returns CVE where the data source of the CVE is the value that is passed to `sourceIdentifier`.
    :type sourceIdentifier: str

    :param versionEnd: Must be combined with `versionEndType` and `virtualMatchString`. Returns only the CVEs associated with CPEs in specific version ranges.
    :type versionEnd: str

    :param versionEndType: Must be combined with `versionEnd` and `virtualMatchString`. Valid values are `including` or `excluding`. Denotes to include the specified version in `versionEnd`, or exclude it.
    :type versionEndType: str

    :param versionStart: Must be combined with `versionStartType` and `virtualMatchString`. Returns only CVEs with specific versions. Requests that include `versionStart` cannot include a version component in the `virtualMatchString`.
    :type versionStart: str

    :param versionStartType: Must be combined with `versionStart` and `virtualMatchString`. Valid values are `including` or `excluding`. Denotes to include the specified version in `versionStart`, or exclude it.
    :type versionStartType: str

    :param virtualMatchString: A more broad filter compared to `cpeName`. The cpe match string that is passed to `virtualMatchString` is compared against the CPE Match Criteria present on CVE applicability statements.
    :type virtualMatchString: str

    :param limit: Custom argument to limit the number of results of the search. Allowed any number between 1 and 2000.
    :type limit: int

    :param delay: Can only be used if an API key is provided. This allows the user to define a delay. The delay must be greater than 0.6 seconds. The NVD API recommends scripts sleep for atleast 6 seconds in between requests.
    :type delay: float

    :param key: NVD API Key. Allows for the user to define a delay. NVD recommends scripts sleep 6 seconds in between requests. If no valid API key is provided, requests are sent with a 6 second delay.
    :type key: str
    """

    parameters, headers = __buildCVECall(
        cpeName,
        cveId,
        cvssV2Metrics,
        cvssV2Severity,
        cvssV3Metrics,
        cvssV3Severity,
        cweId,
        hasCertAlerts,
        hasCertNotes,
        hasKev,
        hasOval,
        isVulnerable,
        keywordExactMatch,
        keywordSearch,
        lastModStartDate,
        lastModEndDate,
        noRejected,
        pubStartDate,
        pubEndDate,
        sourceIdentifier,
        versionEnd,
        versionEndType,
        versionStart,
        versionStartType,
        virtualMatchString,
        limit,
        delay,
        key)

    # raw is the raw dictionary response.
    raw = __get('cve', headers, parameters, limit, delay)
    cves = []
    # Generates the CVEs into objects for easy access and appends them to self.cves
    for eachCVE in raw['vulnerabilities']:
        cves.append(__convert('cve', eachCVE['cve']))
    return cves


def searchCVE_V2(
        cpeName: Optional[str] = None,
        cveId: Optional[str] = None,
        cvssV2Metrics: Optional[str] = None,
        cvssV2Severity: Optional[str] = None,
        cvssV3Metrics: Optional[str] = None,
        cvssV3Severity: Optional[str] = None,
        cweId: Optional[str] = None,
        hasCertAlerts: Optional[bool] = None,
        hasCertNotes: Optional[bool] = None,
        hasKev: Optional[bool] = None,
        hasOval: Optional[bool] = None,
        isVulnerable: Optional[bool] = None,
        keywordExactMatch: Optional[bool] = None,
        keywordSearch: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        noRejected: Optional[bool] = None,
        pubStartDate: Optional[Union[str, datetime]] = None,
        pubEndDate: Optional[Union[str, datetime]] = None,
        sourceIdentifier: Optional[str] = None,
        versionEnd: Optional[str] = None,
        versionEndType: Optional[str] = None,
        versionStart: Optional[str] = None,
        versionStartType: Optional[str] = None,
        virtualMatchString: Optional[str] = None,
        limit: Optional[int] = None,
        delay: Optional[float] = None,
        key: Optional[str] = None,
        verbose: Optional[bool] = None
) -> Generator[List[CVE], Tuple[str, Any], None]:
    """Build and send GET request then return list of objects containing a collection of CVEs. For more information on the parameters available, please visit https://nvd.nist.gov/developers/vulnerabilities 

    :param cpeName: This value will be compared agains the CPE Match Criteria within a CVE applicability statement. (i.e. find the vulnerabilities attached to that CPE). Partial match strings are allowed.
    :type cpeName: str

    :param cveId: Returns a single CVE that already exists in the NVD.
    :type cveId: str

    :param cvssV2Metrics: This parameter returns only the CVEs that match the provided CVSSv2 vector string. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV3Metrics.
    :type cvssV2Metrics: str

    :param cvssV2Severity: Find vulnerabilities having a 'LOW', 'MEDIUM', or 'HIGH' version 2 severity.
    :type cvssV2Severity: str

    :param cvssV3Metrics: This parameter returns only the CVEs that match the provided CVSSv3 vector string. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV2Metrics.
    :type cvssV3Metrics: str

    :param cvssV3Severity: Find vulnerabilities having a 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL' version 3 severity.
    :type cvssV3Severity: str

    :param cweId: Filter collection by CWE (Common Weakness Enumeration) ID. You can find a list at https://cwe.mitre.org/. A CVE can have multiple CWE IDs assigned to it.
    :type cweId: str

    :param hasCertAlerts: Returns CVE that contain a Technical Alert from US-CERT.
    :type hasCertAlerts: bool

    :param hasCertNotes: Returns CVE that contain a Vulnerability Note from CERT/CC.
    :type hasCertNotes: bool

    :param hasKev: Returns CVE that appear in CISAs Known Exploited Vulnerabilities (KEV) catalog.
    :type hasKev: bool

    :param hasOval: Returns CVE that contain information from MITRE's Open Vulnerability and Assessment Language (OVAL) before this transitioned to the Center for Internet Security (CIS).
    :type hasOval: bool

    :param isVulnerable: Returns CVE associated with a specific CPE, where the CPE is also considered vulnerable. **REQUIRES** `cpeName` parameter. `isVulnerable` is not compatible with `virtualMatchString` parameter.
    :type isVulnerable: bool    

    :param keywordExactMatch: When `keywordSearch` is used along with `keywordExactmatch`, it will search the NVD for CVEs containing exactly what was passed to `keywordSearch`. **REQUIRES** `keywordSearch`.
    :type keywordExactMatch: bool

    :param keywordSearch: Searches CVEs where a word or phrase is found in the current description. If passing multiple keywords with a space character in between then each word must exist somewhere in the description, not necessarily together unless `keywordExactMatch=True` is passed to `searchCVE`.
    :type keywordSearch: str

    :param lastModStartDate: These parameters return only the CVEs that were last modified during the specified period. If a CVE has been modified more recently than the specified period, it will not be included in the response. If filtering by the last modified date, both `lastModStartDate` and `lastModEndDate` are REQUIRED. The maximum allowable range when using any date range parameters is 120 consecutive days.
    :type lastModStartDate: str,datetime obj

    :param lastModEndDate: Required if using lastModStartDate.
    :type lastModEndDate: str, datetime obj

    :param noRejected: Filters out all CVEs that are in a reject or rejected status. Searches without this parameter include rejected CVEs.
    :type noRejected: bool

    :param pubStartDate: These parameters return only the CVEs that were added to the NVD (i.e., published) during the specified period. If filtering by the published date, both `pubStartDate` and `pubEndDate` are REQUIRED. The maximum allowable range when using any date range parameters is 120 consecutive days.
    :type pubStartDate: str,datetime obj

    :param pubEndDate: Required if using pubStartDate.
    :type pubEndDate: str, datetime obj

    :param sourceIdentifier: Returns CVE where the data source of the CVE is the value that is passed to `sourceIdentifier`.
    :type sourceIdentifier: str

    :param versionEnd: Must be combined with `versionEndType` and `virtualMatchString`. Returns only the CVEs associated with CPEs in specific version ranges.
    :type versionEnd: str

    :param versionEndType: Must be combined with `versionEnd` and `virtualMatchString`. Valid values are `including` or `excluding`. Denotes to include the specified version in `versionEnd`, or exclude it.
    :type versionEndType: str

    :param versionStart: Must be combined with `versionStartType` and `virtualMatchString`. Returns only CVEs with specific versions. Requests that include `versionStart` cannot include a version component in the `virtualMatchString`.
    :type versionStart: str

    :param versionStartType: Must be combined with `versionStart` and `virtualMatchString`. Valid values are `including` or `excluding`. Denotes to include the specified version in `versionStart`, or exclude it.
    :type versionStartType: str

    :param virtualMatchString: A more broad filter compared to `cpeName`. The cpe match string that is passed to `virtualMatchString` is compared against the CPE Match Criteria present on CVE applicability statements.
    :type virtualMatchString: str

    :param limit: Custom argument to limit the number of results of the search. Allowed any number between 1 and 2000.
    :type limit: int

    :param delay: Can only be used if an API key is provided. This allows the user to define a delay. The delay must be greater than 0.6 seconds. The NVD API recommends scripts sleep for atleast 6 seconds in between requests.
    :type delay: float

    :param key: NVD API Key. Allows for the user to define a delay. NVD recommends scripts sleep 6 seconds in between requests. If no valid API key is provided, requests are sent with a 6 second delay.
    :type key: str
    """

    parameters, headers = __buildCVECall(
        cpeName,
        cveId,
        cvssV2Metrics,
        cvssV2Severity,
        cvssV3Metrics,
        cvssV3Severity,
        cweId,
        hasCertAlerts,
        hasCertNotes,
        hasKev,
        hasOval,
        isVulnerable,
        keywordExactMatch,
        keywordSearch,
        lastModStartDate,
        lastModEndDate,
        noRejected,
        pubStartDate,
        pubEndDate,
        sourceIdentifier,
        versionEnd,
        versionEndType,
        versionStart,
        versionStartType,
        virtualMatchString,
        limit,
        delay,
        key)

    # Send the GET request. Get a generator object that returns batched
    # responses converted to dictionaries
    for batch in __get_with_generator('cve', headers, parameters, limit, delay):
        for eachCVE in batch['vulnerabilities']:
            yield __convert('cve', eachCVE['cve'])


def __buildCVECall(
        cpeName: Optional[str] = None,
        cveId: Optional[str] = None,
        cvssV2Metrics: Optional[str] = None,
        cvssV2Severity: Optional[str] = None,
        cvssV3Metrics: Optional[str] = None,
        cvssV3Severity: Optional[str] = None,
        cweId: Optional[str] = None,
        hasCertAlerts: Optional[bool] = None,
        hasCertNotes: Optional[bool] = None,
        hasKev: Optional[bool] = None,
        hasOval: Optional[bool] = None,
        isVulnerable: Optional[bool] = None,
        keywordExactMatch: Optional[bool] = None,
        keywordSearch: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        noRejected: Optional[bool] = None,
        pubStartDate: Optional[Union[str, datetime]] = None,
        pubEndDate: Optional[Union[str, datetime]] = None,
        sourceIdentifier: Optional[str] = None,
        versionEnd: Optional[str] = None,
        versionEndType: Optional[str] = None,
        versionStart: Optional[str] = None,
        versionStartType: Optional[str] = None,
        virtualMatchString: Optional[str] = None,
        limit: Optional[int] = None,
        delay: Optional[float] = None,
        key: Optional[str] = None,
        verbose: Optional[bool] = None
) -> Tuple[Dict[str, Union[str, bool, None]], Dict[str, str]]:

    parameters = {}

    if cpeName is not None:
        cpeName = urllib.parse.quote_plus(cpeName, encoding='utf-8')
        parameters['cpeName'] = cpeName

    if cveId is not None:
        parameters['cveId'] = cveId

    if cvssV2Metrics is not None:
        cvssV2Metrics = urllib.parse.quote_plus(
            cvssV2Metrics, encoding='utf-8')
        parameters['cvssV2Metrics'] = cvssV2Metrics

    if cvssV2Severity is not None:
        cvssV2Severity = cvssV2Severity.upper()
        if cvssV2Severity in ['LOW', 'MEDIUM', 'HIGH']:
            parameters['cvssV2Severity'] = cvssV2Severity
        else:
            raise SyntaxError(
                "cvssV2Severity parameter can only be assigned LOW, MEDIUM, or HIGH value.")

    if cvssV3Metrics is not None:
        cvssV3Metrics = urllib.parse.quote_plus(
            cvssV3Metrics, encoding='utf-8')
        parameters['cvssV3Metrics'] = cvssV3Metrics

    if cvssV3Severity is not None:
        cvssV3Severity = cvssV3Severity.upper()
        if cvssV3Severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            parameters['cvssV3Severity'] = cvssV3Severity
        else:
            raise SyntaxError(
                "cvssV3Severity parameter can only be assigned LOW, MEDIUM, HIGH, or CRITICAL value.")

    if cweId is not None:
        parameters['cweId'] = cweId.upper()

    if hasCertAlerts is not None:
        parameters['hasCertAlerts'] = None

    if hasCertNotes is not None:
        parameters['hasCertNotes'] = None

    if hasKev is not None:
        parameters['hasKev'] = None

    if hasOval is not None:
        parameters['hasOval'] = None

    if isVulnerable is not None:
        if cpeName is not None:
            parameters['isVulnerable'] = isVulnerable
        else:
            raise SyntaxError(
                'cpeName parameter must be defined if isVulnerable parameter is passed.')

    if keywordExactMatch is not None:
        if keywordSearch:
            parameters['keywordExactMatch'] = None
        else:
            raise SyntaxError(
                'keywordSearch parameter must be passed if keywordExactMatch is set to True.')

    if keywordSearch is not None:
        parameters['keywordSearch'] = keywordSearch

    if lastModStartDate is not None:
        if isinstance(lastModStartDate, datetime):
            date = lastModStartDate.isoformat()
        elif isinstance(lastModStartDate, str):
            date = datetime.strptime(
                lastModStartDate, '%Y-%m-%d %H:%M').isoformat()
        else:
            raise SyntaxError('Invalid date syntax: ' + lastModStartDate)
        parameters['lastModStartDate'] = date.replace('+', '%2B')

    if lastModEndDate is not None:
        if isinstance(lastModEndDate, datetime):
            date = lastModEndDate.isoformat()
        elif isinstance(lastModEndDate, str):
            date = datetime.strptime(
                lastModEndDate, '%Y-%m-%d %H:%M').isoformat()
        else:
            raise SyntaxError('Invalid date syntax: ' + lastModEndDate)
        parameters['lastModEndDate'] = date.replace('+', '%2B')

    if noRejected is not None:
        parameters['noRejected'] = None

    if pubStartDate is not None:
        if isinstance(pubStartDate, datetime):
            date = pubStartDate.isoformat()
        elif isinstance(pubStartDate, str):
            date = datetime.strptime(
                pubStartDate, '%Y-%m-%d %H:%M').isoformat()
        else:
            raise SyntaxError('Invalid date syntax: ' + pubEndDate)
        parameters['pubStartDate'] = date.replace('+', '%2B')

    if pubEndDate:
        if isinstance(pubEndDate, datetime):
            date = pubEndDate.isoformat()
        elif isinstance(pubEndDate, str):
            date = datetime.strptime(
                pubEndDate, '%Y-%m-%d %H:%M').isoformat()
        else:
            raise SyntaxError('Invalid date syntax: ' + pubEndDate)
        parameters['pubEndDate'] = date.replace('+', '%2B')

    if sourceIdentifier is not None:
        parameters['sourceIdentifier'] = sourceIdentifier

    if virtualMatchString is not None:
        virtualMatchString = urllib.parse.quote_plus(
            virtualMatchString, encoding='utf-8')
        parameters['virtualMatchString'] = virtualMatchString

    if versionEnd is not None or versionEndType is not None:
        if versionEnd is not None and versionEndType is not None and virtualMatchString is not None:
            if versionEndType not in ['including', 'excluding']:
                raise SyntaxError(
                    'versionEnd parameter must be either "including" or "excluding".')
            else:
                parameters['versionEnd'] = str(versionEnd)
                parameters['versionEndType'] = versionEndType
        else:
            raise SyntaxError(
                'If versionEnd is used, all three parameters versionEnd, versionEndType, and virtualMatchString are required.')

    if versionStart is not None or versionStartType is not None:
        if versionStart and versionStartType and virtualMatchString:
            if versionStartType not in ['including', 'excluding']:
                raise SyntaxError(
                    'versionStart parameter must be either "including" or "excluding".')
            else:
                parameters['versionStart'] = str(versionStart)
                parameters['versionStartType'] = versionStartType
        else:
            raise SyntaxError(
                'If versionStart is used, all three parameters versionStart, versionStartType, and virtualMatchString are required.')

    if limit is not None:
        if limit > 2000 or limit < 1:
            raise SyntaxError('Limit parameter must be between 1 and 2000')
        parameters['resultsPerPage'] = str(limit)

    if key is not None:
        headers = {'content-type': 'application/json', 'apiKey': key}
    else:
        headers = {'content-type': 'application/json'}

    if delay is not None and key is not None:
        if delay < 0.6:
            raise SyntaxError(
                'Delay parameter must be greater than 0.6 seconds with an API key. NVD API recommends several seconds.')
    elif delay is not None and key is None:
        raise SyntaxError(
            'Key parameter must be present to define a delay. Requests are delayed 6 seconds without an API key by default.')

    return parameters, headers
