from typing import Literal, Dict, Mapping, Union, Optional, LiteralString, Generator, Any

import requests
import time
import logging

from json.decoder import JSONDecodeError

logger = logging.getLogger(__name__)

def __get(
        product: Literal["cve", "cpe", "cpeMatch"],
        headers: Mapping[str, Union[str, bytes, None]],
        parameters: Dict[str, Union[str, LiteralString, int]],
        limit: Optional[int] = None,
        delay: Optional[float] = None
) -> Dict[str, Any]:
    """Calculate required pages for multiple requests, send the GET request with the search criteria, return list of CVEs or CPEs objects."""

    # Get the default 2000 items to see the totalResults and determine pages required.
    if product == 'cve':
        link = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'
    elif product == 'cpe':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/2.0?'
    elif product == 'cpeMatch':
        link = 'https://services.nvd.nist.gov/rest/json/cpematch/2.0?'

    # Requests doesn't really work with dictionary parameters that have no value like `isVulnerable`. The workaround is to just pass a string instead.
    # This joins the parameters into a string with '&' and if a key contains a value then it will join the values with '='
    stringParams = '&'.join(
        [k if v is None else f"{k}={v}" for k, v in parameters.items()])
    logger.debug("Filter:\n%s", link + stringParams)

    raw = requests.get(link, params=stringParams, headers=headers, timeout=30)
    raw.encoding = 'utf-8'
    raw.raise_for_status()

    try:  # Try to convert the request to JSON. If it is not JSON, then log the response and exit.
        raw = raw.json()
        if 'message' in raw:
            raise LookupError(raw['message'])
    except JSONDecodeError:
        logger.error("Invalid search criteria syntax: %s", str(raw))
        logger.error("Attempted search criteria: %s", str(parameters))

    if delay is None:
        delay = 6
    time.sleep(delay)

    # If a limit is in the search criteria or the total number of results are less than or equal to the default 2000 that were just requested, return and don't request anymore.
    totalResults = raw['totalResults']
    if limit is not None or totalResults <= 2000:
        return raw

    # If the results is more than the API limit, figure out how many pages there are and calculate the number of requests.
    # Use the page we already grabbed, then send a request starting at startIndex = 2000, then get the next page and ask for 2000 more results at the 2000th index result until all results have been grabbed.
    # Add each ['vulnerabilities'] or ['products'] list from each page to the end of the first request. Effectively creates one data point.
    elif totalResults > 2000:
        pages = (totalResults // 2000)
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
            logger.debug("Filter:\n%s", link + stringParams)
            try:
                getReq = requests.get(
                    link, params=stringParams, headers=headers, timeout=30)
                getReq.encoding = 'utf-8'
                getData = getReq.json()[path]
                time.sleep(delay)
            except JSONDecodeError:
                logger.error('JSONDecodeError')
                logger.error('Something went wrong: %s', str(getReq))
                logger.error('Attempted search criteria: %s', str(stringParams))
                logger.error('URL: %s', getReq.request.url)
                getReq.raise_for_status()
            rawTemp.extend(getData)
            startIndex += 2000
        raw[path] = rawTemp
        return raw


def __get_with_generator(
        product: Literal["cve", "cpe", "cpeMatch"],
        headers: Mapping[str, Union[str, bytes, None]],
        parameters: Dict[str, Union[str, LiteralString, int]],
        limit: Optional[int],
        delay: float=6
) -> Generator[Any, None, None]:
    # Get the default 2000 items to see the totalResults and determine pages required.
    if product == 'cve':
        link = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'
    elif product == 'cpe':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/2.0?'
    elif product == 'cpeMatch':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/2.0?'
    startIndex = 0
    while True:
        stringParams = '&'.join(
            [k if v is None else f"{k}={v}" for k, v in parameters.items()])
        logger.debug("Filter:\n%s", link + stringParams)
        rate_delay = 1
        while True:
            raw = requests.get(link, params=stringParams,
                               headers=headers, timeout=30)
            if raw.status_code == 403:
                logger.error("Request returned a rate limit error. Retrying in %f seconds...", rate_delay)
                time.sleep(rate_delay)
                rate_delay *= 2
            else:
                break

        raw.encoding = 'utf-8'
        raw.raise_for_status()

        try:  # Try to convert the request to JSON. If it is not JSON, then log the response and exit.
            raw = raw.json()
            if 'message' in raw:
                raise LookupError(raw['message'])
        except JSONDecodeError:
            logger.error("Invalid search criteria syntax: %s", str(raw))
            logger.error("Attempted search criteria: %s", str(parameters))
        yield raw

        totalResults = raw['totalResults']

        startIndex += 2000
        parameters['startIndex'] = str(startIndex)
        parameters['resultsPerPage'] = '2000'

        if startIndex == 0:
            logger.debug("Query returned %d total records", totalResults)

        if limit is None:
            if startIndex < totalResults:
                logger.debug("Getting %s batch %d to %d", product, raw["startIndex"], startIndex)
            else:
                logger.debug("Getting %s batch %d to %d", product, raw["startIndex"], totalResults)

        if limit is not None or startIndex > totalResults:
            break

        time.sleep(delay)
