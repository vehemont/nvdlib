import requests
import datetime
import time

from json.decoder import JSONDecodeError
from datetime import datetime
from .classes import __convert
from .get import __get

def getCVE(CVEID, cpe_dict):
    """Build and send GET request for a single CVE then return object containing CVE attributes.

    :param CVEID: String of the CVE ID of the vulnerability to retrieve more details.
    :type CVEID: str

    :param cpe_dict: Required True/False Boolean. Allows you to control whether matching CPE names from the Official Dictionary are included in the response.
    :type cpe_dict: Bool True

    """
    def __get(CVEID, cpe_dict):
        link = 'https://services.nvd.nist.gov/rest/json/cve/1.0/'
        time.sleep(0.1) # Rate limit safety
        if cpe_dict == True:
            searchCriteria = link + CVEID + '?addOns=dictionaryCpes'
            raw = requests.get(searchCriteria)
        elif cpe_dict == False:
            searchCriteria = link + CVEID
            raw = requests.get(searchCriteria)
        else:
            raise TypeError("cpe_dict parameter must be boolean True or False.")
        try:
            raw = raw.json()
            if 'message' in raw: # If no results were found raise error with the message provided from the API
                raise LookupError(raw['message'])

        except JSONDecodeError:
            print('Invalid CVE: ' + str(raw))
            print('Attempted search for CVE ID : ' + CVEID)
            exit()
        return raw

    raw = __get(CVEID, cpe_dict)    
    return __convert('cve', raw['result']['CVE_Items'][0])



def searchCVE(**kwargs):
    """Build and send GET request then return list of objects containing a collection of CVEs.

    :param pubStartDate: The pubStartDate and pubEndDate parameters specify the set of CVE that were added to NVD (published) during the period. 
        It is not necessary to provide both start and end dates if your goal is to retrieve all CVE after a certain date, or up to a certain date. All times are in UTC 00:00.
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

    :param cpe_dict: -- When the request has this parameter, the response returns official CPE names for each CPE match
        string in the configuration, in so far as they are present in the Official CPE Dictionary.

        **Warning:** If your search contains many results, the response will be very large as it will contain every CPE that a vulnerability has, thus resulting in delays.
    :type cpe_dict: bool True

    :param limit: -- Custom argument to limit the number of results of the search. Allowed any number between 1 and 2000.
    :type limit: int
    
    """
    def __buildCVECall(kwargs):
        parameters = []
        if 'keyword' in kwargs:
            keyword = 'keyword=' + kwargs['keyword']
            parameters.append(keyword)

        if 'pubStartDate' in kwargs:
            date = str(datetime.strptime(kwargs['pubStartDate'], '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            pubStartDate = 'pubStartDate=' + date
            parameters.append(pubStartDate)
        
        if 'pubEndDate' in kwargs:
            date = str(datetime.strptime(kwargs['pubEndDate'], '%Y-%m-%d %H:%M').isoformat())  + ':000 UTC-00:00'
            pubEndDate = 'pubEndDate=' + date
            parameters.append(pubEndDate)

        if 'modStartDate' in kwargs:
            date = str(datetime.strptime(kwargs['modStartDate'], '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            modStartDate = 'modStartDate=' + date
            parameters.append(modStartDate)

        if 'modEndDate' in kwargs:
            date = str(datetime.strptime(kwargs['modEndDate'], '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            modEndDate = 'modEndDate=' + date
            parameters.append(modEndDate)                

        if 'includeMatchStringChange' in kwargs:
            if kwargs['includeMatchStringChange'] == True:
                includeMatchStringChange = 'includeMatchStringChange=true'
                parameters.append(includeMatchStringChange)
            else:
                raise TypeError("includeMatchStringChange parameter can only be boolean True.")

        if 'exactMatch' in kwargs:
            if kwargs['exactMatch'] == True:
                exactMatch = 'isExactMatch=true'
                parameters.append(exactMatch)
            else:
                raise TypeError("exactMatch parameter can only be boolean True.")

        if 'cvssV2Severity' in kwargs:
            cvssV2Severity = kwargs['cvssV2Severity'].upper()
            if cvssV2Severity in ['LOW', 'MEDIUM', 'HIGH']:
                cvssV2Severity = 'cvssV2Severity=' + cvssV2Severity
                parameters.append(cvssV2Severity)
            else:
                raise ValueError("cvssV2Severity parameter can only be assigned LOW, MEDIUM, or HIGH value.")

        if 'cvssV3Severity' in kwargs:
            cvssV3Severity = kwargs['cvssV3Severity'].upper()
            if cvssV3Severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                cvssV3Severity = 'cvssV3Severity=' + cvssV3Severity
                parameters.append(cvssV3Severity)
            else:
                raise ValueError("cvssV3Severity parameter can only be assigned LOW, MEDIUM, HIGH, or CRITICAL value.")

        if 'cvssV2Metrics' in kwargs:
            cvssV2Metrics = 'cvssV2Metrics=' + kwargs['cvssV2Metrics']
            parameters.append(cvssV2Metrics)
        
        if 'cvssV3Metrics' in kwargs:
            cvssV3Metrics = 'cvssV3Metrics=' + kwargs['cvssV3Metrics']
            parameters.append(cvssV3Metrics)

        if 'cpeMatchString' in kwargs:
            cpeMatchString = 'cpeMatchString=' + kwargs['cpeMatchString']
            parameters.append(cpeMatchString)
        
        if 'cpeName' in kwargs:
            cpeName = 'cpeName=' + kwargs['cpeName']
            parameters.append(cpeName)

        if 'cpe_dict' in kwargs:
            if kwargs['cpe_dict'] == True:
                cpe_dict = 'addOns=dictionaryCpes'
                parameters.append(cpe_dict)
            else:
                raise TypeError("cpe_dict parameter can only be boolean True.")

        if 'cweId' in kwargs:
            cweId = 'cweId=' + kwargs['cweId']
            parameters.append(cweId)

        if 'limit' in kwargs:
            limit = 'resultsPerPage=' + str(kwargs['limit'])
            if kwargs['limit'] > 5000 or kwargs['limit'] < 1:
                raise ValueError('Limit parameter must be between 1 and 5000')
            parameters.append(limit)
        return parameters

    parameters = __buildCVECall(kwargs)

    # raw is the raw dictionary response.
    raw = __get('cve', parameters, kwargs)
    cves = []
    # Generates the CVEs into objects for easy access and appends them to self.cves
    for eachCVE in raw['result']['CVE_Items']:
        cves.append(__convert('cve', eachCVE))
    return cves