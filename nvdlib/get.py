import time
from json.decoder import JSONDecodeError

import requests
from requests.adapters import HTTPAdapter, Retry

DEFAULT_RETRIES = 5
DEFAULT_BACKOFF = 0.3
# https://requests.readthedocs.io/en/latest/user/advanced/#timeouts
DEFAULT_CONNECT_TIMEOUT = 6.1
DEFAULT_READ_TIMEOUT = 90

def session_with_retries(max_retries: int = DEFAULT_RETRIES,
                         backoff_factor: float = DEFAULT_BACKOFF,
                         proxies: dict = None) -> requests.Session:
    new_session = requests.Session()
    retries = Retry(total=max_retries,
                    connect=max_retries,
                    read=max_retries,
                    status=max_retries,
                    allowed_methods=frozenset(['HEAD', 'GET', 'POST']),
                    status_forcelist=frozenset([403, 500, 502, 503, 504]),
                    backoff_factor=backoff_factor,
                    )
    retry_adapter = HTTPAdapter(max_retries=retries)
    new_session.mount('http://', retry_adapter)
    new_session.mount('https://', retry_adapter)
    if proxies is not None:
        new_session.proxies.update(proxies)
    return new_session

def __get(product, headers, parameters, limit, verbose, delay):
    """Calculate required pages for multiple requests, send the GET request with the search criteria, return list of CVEs or CPEs objects."""

    # Get the default 2000 items to see the totalResults and determine pages required.
    if product == 'cve':
        link = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'
    elif product == 'cpe':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/2.0?'

    # Requests doesn't really work with dictionary parameters that have no value like `isVulnerable`. The workaround is to just pass a string instead.
    # This joins the parameters into a string with '&' and if a key contains a value then it will join the values with '='
    stringParams = '&'.join(
        [k if v is None else f"{k}={v}" for k, v in parameters.items()])
    if verbose:
        print('Filter:\n' + link + stringParams)

    s = session_with_retries()
    raw = s.get(link, params=stringParams, headers=headers, 
                timeout=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT))

    raw.encoding = 'utf-8'
    raw.raise_for_status()

    try:  # Try to convert the request to JSON. If it is not JSON, then print the response and exit.
        raw = raw.json()
        if 'message' in raw:
            raise LookupError(raw['message'])
    except JSONDecodeError:
        print('Invalid search criteria syntax: ' + str(raw))
        print('Attempted search criteria: ' + str(parameters))

    if not delay:
        delay = 6
    time.sleep(delay)

    # If a limit is in the search criteria or the total number of results are less than or equal to the default 2000 that were just requested, return and don't request anymore.
    totalResults = raw['totalResults']
    if limit or totalResults <= 2000:
        return raw

    # If the results is more than the API limit, figure out how many pages there are and calculate the number of requests.
    # Use the page we already grabbed, then send a request starting at startIndex = 2000, then get the next page and ask for 2000 more results at the 2000th index result until all results have been grabbed.
    # Add each ['vulnerabilities'] or ['products'] list from each page to the end of the first request. Effectively creates one data point.
    elif totalResults > 2000:
        pages = totalResults // 2000
        startIndex = 2000
        if product == 'cve':
            path = 'vulnerabilities'
        else:
            path = 'products'

        rawTemp = raw[path]

        for eachPage in range(pages):
            parameters['resultsPerPage'] = '2000'
            parameters['startIndex'] = str(startIndex)
            stringParams = '&'.join(
                [k if v is None else f"{k}={v}" for k, v in parameters.items()])
            if verbose:
                print('Filter:\n' + link + stringParams)
            try:
                getReq = s.get(link, params=stringParams, headers=headers, 
                               timeout=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT))
                getReq.encoding = 'utf-8'
                getData = getReq.json()[path]
                time.sleep(delay)
            except JSONDecodeError:
                print('JSONDecodeError')
                print('Something went wrong: ' + str(getReq))
                print('Attempted search criteria: ' + str(stringParams))
                print('URL: ' + getReq.request.url)
                getReq.raise_for_status()
            rawTemp.extend(getData)
            startIndex += 2000
        raw[path] = rawTemp
        return raw


def __get_with_generator(product, headers, parameters, limit,
                         verbose, delay):
    # Get the default 2000 items to see the totalResults and determine pages required.
    if product == 'cve':
        link = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'
    elif product == 'cpe':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/2.0?'

    startIndex = 0
    while True:
        stringParams = '&'.join(
            [k if v is None else f"{k}={v}" for k, v in parameters.items()])
        if verbose:
            print('Filter:\n' + link + stringParams)
        rate_delay = 1

        s = session_with_retries()
        raw = s.get(link, params=stringParams,
                               headers=headers, timeout=(6.1,90))

        raw.encoding = 'utf-8'
        raw.raise_for_status()

        try:  # Try to convert the request to JSON. If it is not JSON, then print the response and exit.
            raw = raw.json()
            if 'message' in raw:
                raise LookupError(raw['message'])
        except JSONDecodeError:
            print('Invalid search criteria syntax: ' + str(raw))
            print('Attempted search criteria: ' + str(parameters))
        yield raw

        totalResults = raw['totalResults']

        startIndex += 2000
        parameters['startIndex'] = str(startIndex)
        parameters['resultsPerPage'] = '2000'

        if verbose and startIndex == 0:
            if limit:
                print(f'Query returned {limit} total records')
            else:
                print(f'Query returned {totalResults} total records')

        if verbose and not limit:
            if startIndex < totalResults:
                print(
                    f'Getting {product} batch {raw["startIndex"]} to {startIndex}')
            else:
                print(
                    f'Getting {product} batch {raw["startIndex"]} to {totalResults}')

        if limit or startIndex > totalResults:
            break

        if not delay:
            delay = 6
        time.sleep(delay)
