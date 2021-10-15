import json
import requests
import time

from json.decoder import JSONDecodeError
from datetime import datetime


def __convert(product, CVEID):
    """Convert the JSON response to a referenceable object."""
    if product == 'cve':
        vuln = json.loads(json.dumps(CVEID), object_hook= CVE)
        vuln.getvars()
        return vuln
    else:
        cpeEntry = json.loads(json.dumps(CVEID), object_hook= CPE)
        return cpeEntry 


def getCVE(CVEID, cpe_dict):
    """Build and send GET request for a single CVE then return object containing CVE attributes.

    CVEID -- String of the CVE ID of the vulnerability to retrieve more details.

    cpe_dict -- Required True/False Boolean. Allows you to control whether matching CPE names from the Official Dictionary are included in the response.

    Example:
    cve = nvdlib.getCVE('CVE-2021-39334', cpe_dict = False)
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


def __get(product, parameters, kwargs):
    """Calculate required pages for multiple requests, send the GET request with the search criteria, return list of CVEs or CPEs objects."""

    searchCriteria = '&'.join(parameters)

    # Get the default 20 items to see the totalResults and determine pages required.
    if product == 'cve':
        link = 'https://services.nvd.nist.gov/rest/json/cves/1.0?'
    elif product == 'cpe':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/1.0?'
    else:
        raise ValueError('Unknown Product')
    raw = requests.get(link + searchCriteria, timeout=10)
    

    try: # Try to convert the request to JSON. If it is not JSON, then print the response and exit.
        raw = raw.json() 
        if 'message' in raw:
            raise LookupError(raw['message'])
    except JSONDecodeError:
        print('Invalid search criteria syntax: ' + str(raw))
        print('Attempted search criteria: ' + searchCriteria)
        exit()
    
    time.sleep(0.1)
    totalResults = raw['totalResults']

    # If a limit is in the search criteria or the total number of results are less than the default 20 that were just requested, return and don't request anymore.
    if 'limit' in kwargs or totalResults < 20:
        return raw

    # If the total results is less than the API limit (Should be 5k but tests shows me 2k), just grab all the results at once.
    elif totalResults > 20 and totalResults < 2000:
        searchCriteria += '&resultsPerPage=' + str(totalResults)
        raw = requests.get(link + searchCriteria, timeout=10).json()
        return raw

    # If the results is more than the API limit, figure out how many pages there are and calculate the number of requests.
    # Send a request starting at startIndex = 0, then get the next page and ask for 2000 more results at the 2000th index result until all results have been grabbed.
    # Add each ['CVE_Items'] list from each page to the end of the first request. Effectively creates one data point.
    elif totalResults > 2000:
        pages = (totalResults // 2000) + 1
        startIndex = 0
        rawTemp = []
        if product == 'cve':
            for eachPage in range(pages):
                newCriteria = searchCriteria + '&resultsPerPage=' + str(2000) + '&startIndex=' + str(startIndex)
                time.sleep(0.1)
                getData = requests.get(link + newCriteria, timeout=10).json()['result']['CVE_Items']
                for eachCVE in getData:
                    rawTemp.append(eachCVE.copy())
                startIndex += 2000
            raw['result']['CVE_Items'] = rawTemp
            return raw
        elif 'cpe':
            for eachPage in range(pages):
                newCriteria = searchCriteria + '&resultsPerPage=' + str(2000) + '&startIndex=' + str(startIndex)
                time.sleep(0.1)
                getData = requests.get(link + newCriteria, timeout=10).json()['result']['cpes']
                for eachCPE in getData:
                    rawTemp.append(eachCPE.copy())
                startIndex += 2000
            raw['result']['cpes'] = rawTemp
            return raw

def searchCVE(**kwargs):
    """Build and send GET request then return list of objects containing a collection of CVEs.

    Arguments:

    pubStartDate / pubEndDate  -- The pubStartDate and pubEndDate parameters specify the set of CVE that were added to NVD (published) during the period. 
        It is not necessary to provide both start and end dates if your goal is to retrieve all CVE after a certain date, or up to a certain date. All times are in UTC 00:00.

        Example: '2020-06-28 00:00'

    
    modStartDate / modEndDate -- The modStartDate and modEndDate parameters specify CVE that were subsequently modified. All times are in UTC 00:00.

        Example: '2020-06-28 00:00'
    
    includeMatchStringChange -- Takes boolean True. Retrieve vulnerabilities where CPE names changed during the time period. This returns 
        vulnerabilities where either the vulnerabilities or the associated product names were modified.

    keyword -- Word or phrase to search the vulnerability description or reference links.

    exactMatch -- Takes boolean True. If the keyword is a phrase, i.e., contains more than one term, then the isExactMatch parameter may be
        used to influence the response. Use exactMatch to retrieve records matching the exact phrase.
        Otherwise, the results contain any record having any of the terms.

    cvssV2Severity -- Find vulnerabilities having a 'LOW', 'MEDIUM', or 'HIGH' version 2 score.

    cvssV3Severity -- Find vulnerabilities having a 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL' version 3 score.

    cvssV2Metrics / cvssV3Metrics -- If your application supports CVSS vector strings, use the cvssV2Metric or cvssV3Metrics parameter to
        find vulnerabilities having those score metrics. Partial vector strings are supported.

    cpeMatchString -- Use cpeMatchString when you want a broader search against the applicability statements attached to the Vulnerabilities 
        (e.x. find all vulnerabilities attached to a specific product).
    
    cpeName -- Use cpeName when you know what CPE you want to compare against the applicability statements 
        attached to the vulnerability (i.e. find the vulnerabilities attached to that CPE). 

    cpe_dict -- Takes boolean True. When the request has this parameter, the response returns official CPE names for each CPE match
        string in the configuration, in so far as they are present in the Official CPE Dictionary.

        WARNING: If your search contains many results, the response will be very large as it will contain every CPE that a vulnerability has.

    limit -- Custom argument to limit the number of results of the search. Allowed any number between 1 and 2000.

    
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

def searchCPE(**kwargs):
    """Build and send GET request then return list of objects containing a collection of CPEs."""

    def __buildCPECall(kwargs):
        parameters = []

        if 'modStartDate' in kwargs:
            date = str(datetime.strptime(kwargs['modStartDate'], '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            modStartDate = 'modStartDate=' + date
            parameters.append(modStartDate)

        if 'modEndDate' in kwargs:
            date = str(datetime.strptime(kwargs['modEndDate'], '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            modEndDate = 'modEndDate=' + date
            parameters.append(modEndDate)     
        
        if 'includeDeprecated' in kwargs:
            includeDeprecated = 'includeDeprecated=true'
            parameters.append(includeDeprecated)
        
        if 'keyword' in kwargs:
            keyword = 'keyword=' + kwargs['keyword']
            parameters.append(keyword)

        if 'cpeMatchString' in kwargs:
            cpeMatchString = 'cpeMatchString=' + kwargs['cpeMatchString']
            parameters.append(cpeMatchString)

        if 'cves' in kwargs:
            if kwargs['cves'] == True:
                cves = 'addOns=cves'
                parameters.append(cves)
            else:
                raise TypeError("cves parameter can only be boolean True.")

        if 'limit' in kwargs:
            limit = 'resultsPerPage=' + str(kwargs['limit'])
            if kwargs['limit'] > 5000 or kwargs['limit'] < 1:
                raise ValueError('Limit parameter must be between 1 and 5000')
            parameters.append(limit)

        return parameters

    # Build the URL for the request
    parameters = __buildCPECall(kwargs)

    # Send the GET request for the JSON and convert to dictionary
    raw = __get('cpe', parameters, kwargs)

    cpes = []
    # Generates the CVEs into objects for easy referencing and appends them to self.cves
    for eachCPE in raw['result']['cpes']:
        cpe = __convert('cpe', eachCPE)
        cpe.getvars() # Generates cpe.title and cpe.name
        cpes.append(cpe)
    return cpes            
            
class CPE:
    """JSON Dump class for CPEs.

    getvars() -- Assigns commonly used variables to shorter attribute names. Ran automatically after retrieving data.


    Attributes:

    deprecated -- Indicates whether CPE has been deprecated.

    cpe23Uri -- The CPE name.

    lastModifiedDate -- CPE modification date

    titles -- Human-readable CPE titles.

    refs -- Reference links.

    deprecatedBy -- If deprecated=true, one or more CPE that replace this one.

    vulnerabilities -- Optional vulnerabilities associated with this CPE. Must use 'cves = true' argument in searchCPE.
    
    """
    def __init__(self, dict):
        vars(self).update(dict)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())

    def getvars(self):
        self.title = self.titles[0].title
        self.name = self.cpe23Uri


class CVE:
    """JSON Dump class for CVEs.
    
    getvars() -- Assigns commonly used variables to shorter attribute names. Ran automatically after retrieving data.

    Attributes:

    Static Attributes from JSON:

    cve -- CVE ID, description, reference links, CWE.

    configurations -- CPE applicability statements and optional CPE names.

    impact -- CVSS severity scores

    publishedDate -- CVE publication date

    lastModifiedDate -- CVE modified date.


    Custom attributes:

    id -- CVE ID number.

    cwe -- Common Weakness Enumeration Specification (CWE)

    url -- Link to additional details on nvd.nist.gov for that CVE.

    v3score -- List that contains V3 or V2 CVSS score (float 1 - 10) as index 0 and the version that score was taken from as index 1.

    v2/v3vector -- A CVSS score is also represented as a vector string, a compressed textual representation of the values used to derive the score.

    v2/v3severity -- LOW, MEDIUM, HIGH, or CRITICAL (Critical is only available for v3)

    v2/v3exploitability -- Float 1 - 10.

    v2/v3impactScore -- Float 1 - 10.

    """

    def __init__(self, dict):
        vars(self).update(dict)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())

    def getvars(self):
        
        self.id = self.cve.CVE_data_meta.ID
        self.cwe = self.cve.problemtype.problemtype_data
        self.url = 'https://nvd.nist.gov/vuln/detail/' + self.id

        if hasattr(self.impact, 'baseMetricV3'):
            self.v3score = self.impact.baseMetricV3.cvssV3.baseScore
            self.v3vector = self.impact.baseMetricV3.cvssV3.vectorString
            self.v3severity = self.impact.baseMetricV3.cvssV3.baseSeverity
            self.v3exploitability = self.impact.baseMetricV3.exploitabilityScore
            self.v3impactScore = self.impact.baseMetricV3.impactScore

        if hasattr(self.impact, 'baseMetricV2'):
            self.v2score = self.impact.baseMetricV2.cvssV2.baseScore
            self.v2vector = self.impact.baseMetricV2.cvssV2.vectorString
            self.v2severity = self.impact.baseMetricV2.severity
            self.v2exploitability = self.impact.baseMetricV2.exploitabilityScore
            self.v2impactScore = self.impact.baseMetricV2.impactScore
        
        if hasattr(self.impact, 'baseMetricV3'):
            self.score = [self.impact.baseMetricV3.cvssV3.baseScore, 'V3']
        elif hasattr(self.impact, 'baseMetricV2'):
            self.score = [self.impact.baseMetricV2.cvssV2.baseScore, 'V2']