import requests
import datetime
import time

from json.decoder import JSONDecodeError
from datetime import datetime
from .classes import __convert
from .get import __get

def getCVE(CVEID, cpe_dict=False, key=False, verbose=False):
    """Build and send GET request for a single CVE then return object containing CVE attributes.

    :param CVEID: String of the CVE ID of the vulnerability to retrieve more details.
    :type CVEID: str

    :param cpe_dict: Set this value to true to control whether matching CPE names from the Official Dictionary are included in the response.
    :type cpe_dict: Bool True

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param verbose: Prints the URL request for debugging purposes.
    :type verbose: bool

    """
    def __get(CVEID, cpe_dict, key, verbose):
        searchCriteria = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + CVEID + '?'
        if cpe_dict == True:
            searchCriteria = searchCriteria + 'addOns=dictionaryCpes'
            #raw = requests.get(searchCriteria)
        elif type(cpe_dict) != bool:
            raise TypeError("cpe_dict parameter must be boolean True or False.")
        if key: # add the api key to the request
            if type(key) == str:
                if cpe_dict == True:
                    searchCriteria = searchCriteria + '&apiKey=' + key
                else:
                    searchCriteria = searchCriteria + 'apiKey=' + key
            else:
                raise TypeError("key parameter must be string.")
        
        if verbose:
            print('Filter:\n' + searchCriteria)
        
        raw = requests.get(searchCriteria)

        try:
            raw = raw.json()
            if 'message' in raw: # If no results were found raise error with the message provided from the API
                raise LookupError(raw['message'])

        except JSONDecodeError:
            print('Invalid CVE: ' + str(raw))
            print('Attempted search for CVE ID : ' + CVEID)
            exit()

        # NIST 6 second rate limit recommendation on requests without API key - https://nvd.nist.gov/developers
        # Get a key, its easy.
        if key:
            delay = 0.6
        else:
            delay = 6
        time.sleep(delay)

        return raw

    raw = __get(CVEID, cpe_dict, key, verbose)    
    return __convert('cve', raw['result']['CVE_Items'][0])



def searchCVE(
            keyword=False, 
            pubStartDate=False, 
            pubEndDate=False, 
            modStartDate=False, 
            modEndDate=False, 
            includeMatchStringChange=False, 
            exactMatch=False,
            cvssV2Severity=False,
            cvssV3Severity=False,
            cvssV2Metrics=False,
            cvssV3Metrics=False,
            cpeMatchString=False,
            cpeName=False,
            cpe_dict=False,
            cweId=False,
            limit=False,
            key=False,
            verbose=False):
    """Build and send GET request then return list of objects containing a collection of CVEs.

    :param pubStartDate: The pubStartDate and pubEndDate parameters specify the set of CVE that were added to NVD (published) during the period. 
        Maximum 120 day range. It is not necessary to provide both start and end dates if your goal is to retrieve all CVE after a certain date, or up to a certain date. All times are in UTC 00:00.
        Example: '2020-06-28 00:00'
    :type pubStartDate: ISO 8601 date/time

    
    :param pubEndDate: Publish end date. Can be used to get all vulnerabilities published up to a specific date and time. All times are in UTC 00:00.
        Example: '2020-06-28 00:00'
    :type pubEndDate: ISO 8601 date/time

    :param modStartDate: The modStartDate and modEndDate parameters specify CVE that were subsequently modified. All times are in UTC 00:00.
        Example: '2020-06-28 00:00'
    :type modStartDate: ISO 8601 date/time

    :param modEndDate: Modifified end date. Can be used to get all vulnerabilities modfied up to a specific date and time. All times are in UTC 00:00.
    :type modEndDate: ISO 8601 date/time

    :param includeMatchStringChange: Retrieve vulnerabilities where CPE names changed during the time period. This returns 
        vulnerabilities where either the vulnerabilities or the associated product names were modified.
    :type includeMatchStringChange: bool True

    :param keyword: Word or phrase to search the vulnerability description or reference links.
    :type keyword: str

    :param exactMatch: If the keyword is a phrase, i.e., contains more than one term, then the isExactMatch parameter may be
        used to influence the response. Use exactMatch to retrieve records matching the exact phrase.
        Otherwise, the results contain any record having any of the terms.
    :type exactMatch: bool True

    :param cvssV2Severity: Find vulnerabilities having a 'LOW', 'MEDIUM', or 'HIGH' version 2 score.
    :type cvssV2Severity: str

    :param cvssV3Severity: -- Find vulnerabilities having a 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL' version 3 score.
    :type cvssV3Severity: str

    :param cvssV2Metrics / cvssV3Metrics: -- If your application supports CVSS vector strings, use the cvssV2Metric or cvssV3Metrics parameter to
        find vulnerabilities having those score metrics. Partial vector strings are supported.
    :type cvssV2Metrics / cvssV3Metrics: str

    :param cpeMatchString: -- Use cpeMatchString when you want a broader search against the applicability statements attached to the Vulnerabilities 
        (e.x. find all vulnerabilities attached to a specific product).
    :type cpeMatchString: str

    :param cpeName: -- Use cpeName when you know what CPE you want to compare against the applicability statements 
        attached to the vulnerability (i.e. find the vulnerabilities attached to that CPE). 
    :type cpeName: str

    :param cpe_dict: -- Set this value to true to control whether matching CPE from the Official Dictionary for each CVE are included in the response.

        **Warning:** If your search contains many results, the response will be very large as it will contain every CPE that a vulnerability has, thus resulting in delays.
    :type cpe_dict: bool True

    :param limit: -- Custom argument to limit the number of results of the search. Allowed any number between 1 and 2000.
    :type limit: int
    
    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param verbose: Prints the URL request for debugging purposes.
    :type verbose: bool    
    """
    def __buildCVECall(
            keyword, 
            pubStartDate, 
            pubEndDate, 
            modStartDate, 
            modEndDate, 
            includeMatchStringChange, 
            exactMatch,
            cvssV2Severity,
            cvssV3Severity,
            cvssV2Metrics,
            cvssV3Metrics,
            cpeMatchString,
            cpeName,
            cpe_dict,
            cweId,
            limit,
            key):
        
        parameters = []
        
        if keyword:
            keyword = 'keyword=' + keyword
            parameters.append(keyword)

        if pubStartDate:
            date = str(datetime.strptime(pubStartDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            pubStartDate = 'pubStartDate=' + date
            parameters.append(pubStartDate)
        
        if pubEndDate:
            date = str(datetime.strptime(pubEndDate, '%Y-%m-%d %H:%M').isoformat())  + ':000 UTC-00:00'
            pubEndDate = 'pubEndDate=' + date
            parameters.append(pubEndDate)
        
        if modStartDate:
            date = str(datetime.strptime(modStartDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            modStartDate = 'modStartDate=' + date
            parameters.append(modStartDate)

        if modEndDate:
            date = str(datetime.strptime(modEndDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            modEndDate = 'modEndDate=' + date
            parameters.append(modEndDate)

        if includeMatchStringChange:
            if includeMatchStringChange == True:
                includeMatchStringChange = 'includeMatchStringChange=true'
                parameters.append(includeMatchStringChange)
            else:
                raise TypeError("includeMatchStringChange parameter can only be boolean True.")

        if exactMatch:
            if exactMatch == True:
                exactMatch = 'isExactMatch=true'
                parameters.append(exactMatch)
            else:
                raise TypeError("exactMatch parameter can only be boolean True.")

        if cvssV2Severity:
            cvssV2Severity = cvssV2Severity.upper()
            if cvssV2Severity in ['LOW', 'MEDIUM', 'HIGH']:
                cvssV2Severity = 'cvssV2Severity=' + cvssV2Severity
                parameters.append(cvssV2Severity)
            else:
                raise ValueError("cvssV2Severity parameter can only be assigned LOW, MEDIUM, or HIGH value.")

        if cvssV3Severity:
            cvssV3Severity = cvssV3Severity.upper()
            if cvssV3Severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                cvssV3Severity = 'cvssV3Severity=' + cvssV3Severity
                parameters.append(cvssV3Severity)
            else:
                raise ValueError("cvssV3Severity parameter can only be assigned LOW, MEDIUM, HIGH, or CRITICAL value.")

        if cvssV2Metrics:
            cvssV2Metrics = 'cvssV2Metrics=' + cvssV2Metrics
            parameters.append(cvssV2Metrics)
        
        if cvssV3Metrics:
            cvssV3Metrics = 'cvssV3Metrics=' + cvssV3Metrics
            parameters.append(cvssV3Metrics)

        if cpeMatchString:
            cpeMatchString = 'cpeMatchString=' + cpeMatchString
            parameters.append(cpeMatchString)
        
        if cpeName:
            cpeName = 'cpeName=' + cpeName
            parameters.append(cpeName)

        if cpe_dict:
            if cpe_dict == True:
                cpe_dict = 'addOns=dictionaryCpes'
                parameters.append(cpe_dict)
            else:
                raise TypeError("cpe_dict parameter can only be boolean True.")

        if cweId:
            cweId = 'cweId=' + cweId
            parameters.append(cweId)

        if limit:
            if limit > 5000 or limit < 1:
                raise ValueError('Limit parameter must be between 1 and 5000')
            limit = 'resultsPerPage=' + str(limit)
            parameters.append(limit)
        
        if key:
            key = 'apiKey=' + str(key)
            parameters.append(key)

        return parameters

    parameters = __buildCVECall(keyword, 
            pubStartDate, 
            pubEndDate, 
            modStartDate, 
            modEndDate, 
            includeMatchStringChange, 
            exactMatch,
            cvssV2Severity,
            cvssV3Severity,
            cvssV2Metrics,
            cvssV3Metrics,
            cpeMatchString,
            cpeName,
            cpe_dict,
            cweId,
            limit,
            key)

    # raw is the raw dictionary response.
    raw = __get('cve', parameters, limit, key, verbose)
    cves = []
    # Generates the CVEs into objects for easy access and appends them to self.cves
    for eachCVE in raw['result']['CVE_Items']:
        cves.append(__convert('cve', eachCVE))
    return cves