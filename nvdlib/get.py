import asyncio
import time
from json.decoder import JSONDecodeError

import requests
from aiohttp import ClientSession


async def __get(session: ClientSession, product, headers, parameters, limit, verbose, delay):
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

    response = await session.get(url=link, params=stringParams, headers=headers, timeout=30)

    try:  # Try to convert the request to JSON. If it is not JSON, then print the response and exit.
        raw = await response.json()
        if 'message' in raw:
            raise LookupError(raw['message'])
    except JSONDecodeError:
        print('Invalid search criteria syntax: ' + str(raw))
        print('Attempted search criteria: ' + str(parameters))

    if not delay:
        delay = 6
    await asyncio.sleep(delay)

    # If a limit is in the search criteria or the total number of results are less than or equal to the default 2000 that were just requested, return and don't request anymore.
    totalResults = raw['totalResults']
    if limit or totalResults <= 2000:
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
            if verbose:
                print('Filter:\n' + link + stringParams)
            try:
                getReq = await session.get(
                    url=link, params=stringParams, headers=headers, timeout=30)
                all_response = await getReq.json()
                getData = all_response[path]
                await asyncio.sleep(delay)
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

        raw = requests.get(link, params=stringParams,
                           headers=headers, timeout=30)
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
