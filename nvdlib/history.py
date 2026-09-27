import urllib.parse

from typing import Generator, Optional, Union, List, Tuple, Any, Dict
from datetime import datetime
from .classes import __convert, CVEHistory
from .get import __get, __get_with_generator


def searchCVEHistory(
        cveId: Optional[str] = None,
        cveIds: Optional[str] = None,
        changeStartDate: Optional[Union[str, datetime]] = None,
        changeEndDate: Optional[Union[str, datetime]] = None,
        eventName: Optional[str] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None,
        proxies: Optional[Dict] = None,
        asDict: Optional[bool] = None
) -> List[CVEHistory]:
    """Build and send GET request then return list of objects containing CVE change history events. For more information on the parameters available, please visit https://nvd.nist.gov/developers/vulnerabilities

    :param cveId: Returns the complete change history for a single CVE.
    :type cveId: str

    :param cveIds: Returns the complete change history for one or more CVEs from a comma separated list of CVE IDs. Maximum of 100 CVE IDs.
    :type cveIds: str

    :param changeStartDate: Returns CVE changes that happened during the specified period. If filtering by change date, both `changeStartDate` and `changeEndDate` are REQUIRED. The maximum allowable range is 120 consecutive days.
    :type changeStartDate: str,datetime obj

    :param changeEndDate: Required if using changeStartDate.
    :type changeEndDate: str, datetime obj

    :param eventName: Returns changes for a single type of change event, such as 'Initial Analysis' or 'CVE Rejected'.
    :type eventName: str

    :param limit: Custom argument to limit the number of results of the search. Allowed any number between 1 and 5000.
    :type limit: int

    :param key: NVD API Key. Allows for the user to define a delay. NVD recommends scripts sleep 6 seconds in between requests. If no valid API key is provided, requests are sent with a 6 second delay.
    :type key: str

    :param delay: Can only be used if an API key is provided. This allows the user to define a delay. The delay must be greater than 0.6 seconds. The NVD API recommends scripts sleep for atleast 6 seconds in between requests.
    :type delay: float

    :param asDict: Return each change as the plain dictionary from the NVD response instead of a CVEHistory object.
    :type asDict: bool
    """

    parameters, headers = __buildCVEHistoryCall(
        cveId,
        cveIds,
        changeStartDate,
        changeEndDate,
        eventName,
        limit,
        key,
        delay)

    raw = __get('cveHistory', headers, parameters, limit, delay, proxies)
    changes = []
    if not raw:
        return changes
    for eachChange in raw['cveChanges']:
        change = eachChange['change']
        if not asDict:
            change = __convert('cveHistory', change)
        changes.append(change)
    return changes


def searchCVEHistory_V2(
        cveId: Optional[str] = None,
        cveIds: Optional[str] = None,
        changeStartDate: Optional[Union[str, datetime]] = None,
        changeEndDate: Optional[Union[str, datetime]] = None,
        eventName: Optional[str] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None,
        proxies: Optional[Dict] = None,
        asDict: Optional[bool] = None
) -> Generator[CVEHistory, Any, None]:
    """Build and send GET request then return a generator of CVE change history events. Uses the same parameters as `searchCVEHistory`.

    :param cveId: Returns the complete change history for a single CVE.
    :type cveId: str

    :param cveIds: Returns the complete change history for one or more CVEs from a comma separated list of CVE IDs. Maximum of 100 CVE IDs.
    :type cveIds: str

    :param changeStartDate: Returns CVE changes that happened during the specified period. If filtering by change date, both `changeStartDate` and `changeEndDate` are REQUIRED. The maximum allowable range is 120 consecutive days.
    :type changeStartDate: str,datetime obj

    :param changeEndDate: Required if using changeStartDate.
    :type changeEndDate: str, datetime obj

    :param eventName: Returns changes for a single type of change event, such as 'Initial Analysis' or 'CVE Rejected'.
    :type eventName: str

    :param limit: Custom argument to limit the number of results of the search. Allowed any number between 1 and 5000.
    :type limit: int

    :param key: NVD API Key. Allows for the user to define a delay. NVD recommends scripts sleep 6 seconds in between requests. If no valid API key is provided, requests are sent with a 6 second delay.
    :type key: str

    :param delay: Can only be used if an API key is provided. This allows the user to define a delay. The delay must be greater than 0.6 seconds. The NVD API recommends scripts sleep for atleast 6 seconds in between requests.
    :type delay: float

    :param asDict: Return each change as the plain dictionary from the NVD response instead of a CVEHistory object.
    :type asDict: bool
    """

    parameters, headers = __buildCVEHistoryCall(
        cveId,
        cveIds,
        changeStartDate,
        changeEndDate,
        eventName,
        limit,
        key,
        delay)

    for batch in __get_with_generator('cveHistory', headers, parameters, limit, delay, proxies):
        if not batch:
            continue
        for eachChange in batch['cveChanges']:
            change = eachChange['change']
            if not asDict:
                change = __convert('cveHistory', change)
            yield change


def __buildCVEHistoryCall(
        cveId: Optional[str] = None,
        cveIds: Optional[str] = None,
        changeStartDate: Optional[Union[str, datetime]] = None,
        changeEndDate: Optional[Union[str, datetime]] = None,
        eventName: Optional[str] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None
) -> Tuple[Dict[str, Union[str, int]], Dict[str, str]]:

    parameters = {}

    if cveId is not None:
        parameters['cveId'] = cveId

    if cveIds is not None:
        parameters['cveIds'] = cveIds

    if changeStartDate is not None:
        if isinstance(changeStartDate, datetime):
            date = changeStartDate.isoformat()
        elif isinstance(changeStartDate, str):
            date = datetime.strptime(
                changeStartDate, '%Y-%m-%d %H:%M').isoformat()
        else:
            raise SyntaxError('Invalid date syntax: ' + changeStartDate)
        parameters['changeStartDate'] = date.replace('+', '%2B')

    if changeEndDate is not None:
        if isinstance(changeEndDate, datetime):
            date = changeEndDate.isoformat()
        elif isinstance(changeEndDate, str):
            date = datetime.strptime(
                changeEndDate, '%Y-%m-%d %H:%M').isoformat()
        else:
            raise SyntaxError('Invalid date syntax: ' + changeEndDate)
        parameters['changeEndDate'] = date.replace('+', '%2B')

    if eventName is not None:
        parameters['eventName'] = urllib.parse.quote(eventName, encoding='utf-8')

    if limit is not None:
        if limit > 5000 or limit < 1:
            raise SyntaxError('Limit parameter must be between 1 and 5000')
        parameters['resultsPerPage'] = limit

    if key is not None:
        headers = {'content-type': 'application/json', 'apiKey': key}
    else:
        headers = {'content-type': 'application/json'}

    if delay is not None and key is not None:
        if delay < 0.6:
            raise SyntaxError('Delay parameter must be greater than 0.6 seconds with an API key. NVD API recommends several seconds.')
    elif delay is not None and key is None:
        raise SyntaxError('Key parameter must be present to define a delay. Requests are delayed 6 seconds without an API key by default.')

    return parameters, headers
