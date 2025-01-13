import datetime
import urllib.parse

from typing import Generator, Union, Optional, List, Any, Tuple, LiteralString, Dict
from datetime import datetime
from .get import __get, __get_with_generator
from .classes import __convert, CPE


def searchCPE(
        cpeNameId: Optional[str] = None,
        cpeMatchString: Optional[str] = None,
        keywordExactMatch: Optional[bool] = None,
        keywordSearch: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        matchCriteriaId: Optional[str] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None
) -> List[CPE]:
    """Build and send GET request then return list of objects containing a collection of CPEs.
    
    :param cpeNameId: Returns a specific CPE record using its UUID. If a correctly formatted UUID is passed but it does not exist, it will return empty results. The UUID is the `cpeNameId` value when searching CPE.
    :type cpeNameId: str

    :param cpeMatchString: Use a partial CPE name to search for other CPE names. 
    :type cpeMatchString: str

    :param keywordExactMatch: Searches metadata within CPE title and reference links for an exact match of the phrase or word passed to it. Must be included with `keywordSearch`.
    :type keywordExactMatch: bool

    :param keywordSearch: Returns CPE records where a word or phrase is found in the metadata title or reference links. Space characters act as an `AND` statement.
    :type keywordSearch: str

    :param lastModStartDate: CPE last modification start date. Maximum 120 day range. A start and end date is required. All times are in UTC 00:00.

        A datetime object or string can be passed as a date. NVDLib will automatically parse the datetime object into the correct format.

        String Example: '2020-06-28 00:00'
    :type lastModStartDate: str/datetime obj

    :param lastModEndDate: CPE last modification end date. Maximum 120 day range. Must be included with lastModStartDate.
        Example: '2020-06-28 00:00'
    :type lastModEndDate: str/datetime obj

    :param matchCriteriaId: Returns CPE records associated with a match string by its UUID. Requires a properly formatted UUID.
    :type matchCriteriaId: str

    :param limit: Limits the number of results of the search.
    :type limit: int

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param delay: Can only be used if an API key is provided. The amount of time to sleep in between requests. Must be a value above 0.6 seconds if an API key is present. `delay` is set to 6 seconds if no API key is passed.
    :type delay: float
    """



    # Build the URL for the request
    parameters, headers = __buildCPECall(
        cpeNameId,
        cpeMatchString,
        keywordExactMatch,
        keywordSearch,
        lastModStartDate,
        lastModEndDate,
        matchCriteriaId,
        limit,
        key,
        delay)

    # Send the GET request for the JSON and convert to dictionary
    raw = __get('cpe', headers, parameters, limit, delay)
    cpes = []
    # Generates the CVEs into objects for easy referencing and appends them to self.cves
    for eachCPE in raw['products']:
        cpe = __convert('cpe', eachCPE['cpe'])
        cpes.append(cpe)
    return cpes


def searchCPE_V2(
        cpeNameId: Optional[str] = None,
        cpeMatchString: Optional[str] = None,
        keywordExactMatch: Optional[bool] = None,
        keywordSearch: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        matchCriteriaId: Optional[str] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None
) -> Generator[CPE, Any, None]:
    """Build and send GET request then return list of objects containing a collection of CPEs.
    
    :param cpeNameId: Returns a specific CPE record using its UUID. If a correctly formatted UUID is passed but it does not exist, it will return empty results. The UUID is the `cpeNameId` value when searching CPE.
    :type cpeNameId: str

    :param cpeMatchString: Use a partial CPE name to search for other CPE names. 
    :type cpeMatchString: str

    :param keywordExactMatch: Searches metadata within CPE title and reference links for an exact match of the phrase or word passed to it. Must be included with `keywordSearch`.
    :type keywordExactMatch: bool

    :param keywordSearch: Returns CPE records where a word or phrase is found in the metadata title or reference links. Space characters act as an `AND` statement.
    :type keywordSearch: str

    :param lastModStartDate: CPE last modification start date. Maximum 120 day range. A start and end date is required. All times are in UTC 00:00.

        A datetime object or string can be passed as a date. NVDLib will automatically parse the datetime object into the correct format.

        String Example: '2020-06-28 00:00'
    :type lastModStartDate: str/datetime obj

    :param lastModEndDate: CPE last modification end date. Maximum 120 day range. Must be included with lastModStartDate.
        Example: '2020-06-28 00:00'
    :type lastModEndDate: str/datetime obj

    :param matchCriteriaId: Returns CPE records associated with a match string by its UUID. Requires a properly formatted UUID.
    :type matchCriteriaId: str


    :param limit: Limits the number of results of the search.
    :type limit: int

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param delay: Can only be used if an API key is provided. The amount of time to sleep in between requests. Must be a value above 0.6 seconds if an API key is present. `delay` is set to 6 seconds if no API key is passed.
    :type delay: float
    """

    # Build the URL for the request
    parameters, headers = __buildCPECall(
        cpeNameId,
        cpeMatchString,
        keywordExactMatch,
        keywordSearch,
        lastModStartDate,
        lastModEndDate,
        matchCriteriaId,
        limit,
        key,
        delay)

    # Send the GET request. Get a generator object that returns batched
    # responses converted to dictionaries
    for batch in __get_with_generator('cpe', headers, parameters, limit, delay):
        # Generator object that returns converted CPES
        for eachCPE in batch['products']:
            yield __convert('cpe', eachCPE['cpe'])


def __buildCPECall(
        cpeNameId: Optional[str] = None,
        cpeMatchString: Optional[str] = None,
        keywordExactMatch: Optional[bool] = None,
        keywordSearch: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        matchCriteriaId: Optional[str] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None
) -> Tuple[Dict[str, Union[str, bool, LiteralString, int]], Dict[str, str]]:

    parameters = {}

    if cpeNameId is not None:
        parameters['cpeNameId'] = cpeNameId

    if cpeMatchString is not None:
        cpeMatchString = urllib.parse.quote_plus(cpeMatchString, encoding='utf-8')
        parameters['cpeMatchString'] = cpeMatchString

    if keywordExactMatch:
        if keywordSearch is not None:
            parameters['keywordExactMatch'] = keywordExactMatch
        else:
            raise SyntaxError('keywordSearch parameter must be passed if keywordExactMatch is set to True.')
    
    if keywordSearch is not None:
        parameters['keywordSearch'] = keywordSearch
    
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

    if matchCriteriaId is not None:
        parameters['matchCriteriaId'] = matchCriteriaId

    if limit is not None:
        if limit > 2000 or limit < 1:
            raise SyntaxError('Limit parameter must be between 1 and 2000')
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

def __buildCPEMatchCall(
    cveId: Optional[str] = None,
    lastModStartDate: Union[str, datetime] = None,
    lastModEndDate: Union[str, datetime] = None,
    matchCriteriaId: Optional[str] = None,
    matchStringSearch: Optional[str] = None,
    limit: Optional[int] = None,
    key: Optional[str] = None,
    delay: Optional[float] = None
) -> Tuple[Dict[str, Union[str, bool, LiteralString, int]], Dict[str, str]]:

    parameters = {}

    if cveId is not None:
        parameters['cveId'] = cveId
    
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

    if matchCriteriaId is not None:
        parameters['matchCriteriaId'] = matchCriteriaId

    if matchStringSearch is not None:
        parameters['matchStringSearch'] = matchStringSearch

    if limit is not None:
        if limit > 2000 or limit < 1:
            raise SyntaxError('Limit parameter must be between 1 and 2000')
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

def searchCPEmatch(
        cveId: Optional[str] = None,
        lastModStartDate: Optional[Union[str, datetime]] = None,
        lastModEndDate: Optional[Union[str, datetime]] = None,
        matchCriteriaId: Optional[str] = None,
        matchStringSearch: Optional[str] = None,
        limit: Optional[int] = None,
        key: Optional[str] = None,
        delay: Optional[float] = None
) -> List[CPE]:
    """Build and send GET request then return list of objects containing a collection of CPEs.
    
    :param cveId: Returns all matching CPE match strings for a CVE.
    :type cveId: str

    :param lastModStartDate: Match string last modification start date or CPE last modified start date. Maximum 120 day range. A start and end date is required. All times are in UTC 00:00.

        A datetime object or string can be passed as a date. NVDLib will automatically parse the datetime object into the correct format.

        String Example: '2020-06-28 00:00'
    :type lastModStartDate: str/datetime obj

    :param lastModEndDate: CPE last modification end date. Maximum 120 day range. Must be included with lastModStartDate.
        Example: '2020-06-28 00:00'
    :type lastModEndDate: str/datetime obj

    :param matchCriteriaId: Returns CPE records associated with a match string by its UUID. Requires a properly formatted UUID.
    :type matchCriteriaId: str

    :param matchStringSearch: Returns CPE records that match the provided CPE match string. See the NVD API documentation website for more details on how to use CPE match strings. https://nvd.nist.gov/developers/products
    :type matchStringSearch: str

    :param limit: Limits the number of results of the search.
    :type limit: int

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param delay: Can only be used if an API key is provided. The amount of time to sleep in between requests. Must be a value above 0.6 seconds if an API key is present. `delay` is set to 6 seconds if no API key is passed.
    :type delay: float
    """

    # Build the URL for the request
    parameters, headers = __buildCPEMatchCall(
        cveId,
        lastModStartDate,
        lastModEndDate,
        matchCriteriaId,
        matchStringSearch,
        limit,
        key,
        delay)

    # Send the GET request for the JSON and convert to dictionary
    raw = __get('cpeMatch', headers, parameters, limit, delay)
    cpes = []
    # Generates the CVEs into objects for easy referencing and appends them to self.cves
    for eachCPE in raw['matchStrings']:
        cpe = __convert('MatchString', eachCPE['matchString'])
        cpes.append(cpe)
    return cpes
