import datetime

from datetime import datetime
from .get import __get
from .classes import __convert

def searchCPE(modStartDate=False,
        modEndDate=False,
        includeDeprecated=False,
        keyword=False,
        cpeMatchString=False,
        cves=False,
        limit=False,
        key=False,
        verbose=False):
    """Build and send GET request then return list of objects containing a collection of CPEs.
    
    :param modStartDate: CPE modification start date
    :type modStartDate: ISO 8601 date/time
        Example: '2020-06-28 00:00'
        Maximum 120 day range

    :param modEndDate: CPE modification end date
    :type modEndDate: ISO 8601 date/time
        Example: '2020-06-28 00:00'

    :param includeDeprecated: Include deprecated CPE names that have been replaced.
    :type includeDeprecated: Bool True

    :param keyword: Free text keyword search.
    :type keyword: str

    :param cpeMatchString: CPE match string search.
    :type cpeMatchString: str

    :param cves: Return vulnerabilities. 
        **Warning**: This parameter may incur large amounts of results causing delays.
    :type cves: bool True

    :param limit: Limits the number of results of the search.
    :type limit: int

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param verbose: Prints the URL request for debugging purposes.
    :type verbose: bool
    """


    def __buildCPECall(
        modStartDate,
        modEndDate,
        includeDeprecated,
        keyword,
        cpeMatchString,
        cves,
        limit,
        key):

        parameters = []

        if modStartDate:
            date = str(datetime.strptime(modStartDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            modStartDate = 'modStartDate=' + date
            parameters.append(modStartDate)

        if modEndDate:
            date = str(datetime.strptime(modEndDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            modEndDate = 'modEndDate=' + date
            parameters.append(modEndDate)     
        
        if includeDeprecated:
            includeDeprecated = 'includeDeprecated=true'
            parameters.append(includeDeprecated)
        
        if keyword:
            keyword = 'keyword=' + keyword
            parameters.append(keyword)

        if cpeMatchString:
            cpeMatchString = 'cpeMatchString=' + cpeMatchString
            parameters.append(cpeMatchString)

        if cves:
            if cves == True:
                cves = 'addOns=cves'
                parameters.append(cves)
            else:
                raise TypeError("cves parameter can only be boolean True.")

        if limit:
            if limit > 5000 or limit < 1:
                raise ValueError('Limit parameter must be between 1 and 5000')
            limit = 'resultsPerPage=' + str(limit)
            parameters.append(limit)

        if key:
            key = 'apiKey=' + str(key)
            parameters.append(key)

        return parameters

    # Build the URL for the request
    parameters = __buildCPECall(
        modStartDate,
        modEndDate,
        includeDeprecated,
        keyword,
        cpeMatchString,
        cves,
        limit,
        key)

    # Send the GET request for the JSON and convert to dictionary
    raw = __get('cpe', parameters, limit, key, verbose)

    cpes = []
    # Generates the CVEs into objects for easy referencing and appends them to self.cves
    for eachCPE in raw['result']['cpes']:
        cpe = __convert('cpe', eachCPE)
        cpe.getvars() # Generates cpe.title and cpe.name
        cpes.append(cpe)
    return cpes