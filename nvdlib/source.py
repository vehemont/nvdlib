from typing import Generator, Optional, Union, List, Tuple, Any, Dict
from datetime import datetime
from .classes import __convert, Source
from .get import __get, __get_with_generator


def searchSource(
        sourceIdentifier: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None,
        proxies: Optional[Dict] = None,
        asDict: Optional[bool] = None
) -> List[Source]:
    """Build and send GET request then return list of objects containing the organizations that provide NVD data. For more information on the parameters available, please visit https://nvd.nist.gov/developers/data-sources

    :param sourceIdentifier: Returns the source records where the exact value of `sourceIdentifier` is one of the source identifiers.
    :type sourceIdentifier: str

    :param lastModStartDate: Source last modification start date. Maximum 120 day range. A start and end date is required.
    :type lastModStartDate: str/datetime obj

    :param lastModEndDate: Source last modification end date. Maximum 120 day range. Must be included with lastModStartDate.
    :type lastModEndDate: str/datetime obj

    :param limit: Limits the number of results of the search. Allowed any number between 1 and 1000.
    :type limit: int

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param delay: Can only be used if an API key is provided. The amount of time to sleep in between requests. Must be a value above 0.6 seconds if an API key is present. `delay` is set to 6 seconds if no API key is passed.
    :type delay: float

    :param asDict: Return each source as the plain dictionary from the NVD response instead of a Source object.
    :type asDict: bool
    """

    parameters, headers = __buildSourceCall(
        sourceIdentifier,
        lastModStartDate,
        lastModEndDate,
        limit,
        key,
        delay)

    raw = __get('source', headers, parameters, limit, delay, proxies)
    sources = []
    if not raw:
        return sources
    for source in raw['sources']:
        if not asDict:
            source = __convert('source', source)
        sources.append(source)
    return sources


def searchSource_V2(
        sourceIdentifier: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None,
        proxies: Optional[Dict] = None,
        asDict: Optional[bool] = None
) -> Generator[Source, Any, None]:
    """Build and send GET request then return a generator of NVD data sources. Uses the same parameters as `searchSource`.

    :param sourceIdentifier: Returns the source records where the exact value of `sourceIdentifier` is one of the source identifiers.
    :type sourceIdentifier: str

    :param lastModStartDate: Source last modification start date. Maximum 120 day range. A start and end date is required.
    :type lastModStartDate: str/datetime obj

    :param lastModEndDate: Source last modification end date. Maximum 120 day range. Must be included with lastModStartDate.
    :type lastModEndDate: str/datetime obj

    :param limit: Limits the number of results of the search. Allowed any number between 1 and 1000.
    :type limit: int

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param delay: Can only be used if an API key is provided. The amount of time to sleep in between requests. Must be a value above 0.6 seconds if an API key is present. `delay` is set to 6 seconds if no API key is passed.
    :type delay: float

    :param asDict: Return each source as the plain dictionary from the NVD response instead of a Source object.
    :type asDict: bool
    """

    parameters, headers = __buildSourceCall(
        sourceIdentifier,
        lastModStartDate,
        lastModEndDate,
        limit,
        key,
        delay)

    for batch in __get_with_generator('source', headers, parameters, limit, delay, proxies):
        if not batch:
            continue
        for source in batch['sources']:
            if not asDict:
                source = __convert('source', source)
            yield source


def __buildSourceCall(
        sourceIdentifier: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None
) -> Tuple[Dict[str, Union[str, int]], Dict[str, str]]:

    parameters = {}

    if sourceIdentifier is not None:
        parameters['sourceIdentifier'] = sourceIdentifier

    if lastModStartDate is not None:
        if isinstance(lastModStartDate, datetime):
            date = lastModStartDate.isoformat()
        elif isinstance(lastModStartDate, str):
            date = datetime.strptime(lastModStartDate, '%Y-%m-%d %H:%M').isoformat()
        else:
            raise SyntaxError('Invalid date syntax: ' + lastModStartDate)
        parameters['lastModStartDate'] = date.replace('+', '%2B')

    if lastModEndDate is not None:
        if isinstance(lastModEndDate, datetime):
            date = lastModEndDate.isoformat()
        elif isinstance(lastModEndDate, str):
            date = datetime.strptime(lastModEndDate, '%Y-%m-%d %H:%M').isoformat()
        else:
            raise SyntaxError('Invalid date syntax: ' + lastModEndDate)
        parameters['lastModEndDate'] = date.replace('+', '%2B')

    if limit is not None:
        if limit > 1000 or limit < 1:
            raise SyntaxError('Limit parameter must be between 1 and 1000')
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
