Release History
===============

0.7.5 (2023-10-03)
-------------------
**Bugfixes**
- Merged #30. Added a check if the generator hits 403 rate limit error, instead of breaking the entire generator. Delays twice as long to ensure another 403 isn't hit. 

0.7.4 (2023-05-08)
-------------------

**Enhancements**
- Merged #24. Added the new functions for `searchCVE_V2` and `searchCPE_V2`. They have the same arguments as their respective counterparts (`searchCVE` and `searchCPE`), but are defined as a generator instead. Yields after each CVE conversion from the response. This is useful for systems with resource constraints. 

@nthunk single handedly pushed these features. Thank you. 

0.7.3 (2023-03-29)
-------------------

**Bugfixes**

- Merged #22. When using a datetime object in parameters like `pubEndDate`, NVDLib will now replace the `+` character used to denote the time zone with `%2B` in the string of parameters, preventing a 404 error and per the NVD API documentation. Normally this is done automatically within requests, but NVDLib passes the parameters as a string rather than a dictionary natively within requests. 

**Enhancements**
- Merged #23. Set the optional parameters in `searchCVE` and `searchCPE` to `None` instead of `False`. Helps out with linters and type assignment mismatches.

Big thanks to @ntnunk for submitting the PRs for these changes.

0.7.2 (2023-03-14)
-------------------
**Bugfixes**

- Fixed parsing of CPEs names to allow special characters with CPE names to function correctly. 
- Fixed PyTest data, tests are passing now.

**Enhancements**

- Added newer parameters to `nvdlib.searchCVE()`.
    - noRejected - Filter out CVEs that have a status of rejected.
    - versionEnd / versionEndType / versionStart / versionStartType - Used with virtualMatchString to provide filters based on versions within CPE names

0.7.1 (2022-12-19)
-------------------
**Bugfixes**

- Fixed the location of `baseSeverity`. The `baseSeverity` attribute had its location changed and caused lookups with a CVSS version 2 score to fail. 

0.7.0 (2022-10-31)
-------------------

- Overhauled NVDLib to utilize the new version of the NVD API (version 2).
- `nvdlib.getCVE()` no longer exists and is now combined into `nvdlib.searchCVE()` using the `cvdId` parameter.
- `nvdlib.searchCPE()` no longer has the `cves` parameter to pass CVEs. 
- New parameters for `nvdlib.searchCVE()`
- For a full list of changes, see https://nvdlib.com/en/latest/v1/changesv1.html

Happy Halloween! 🎃

0.6.1 (2022-10-18)
-------------------
**Bugfixes**

- Updated `cve.py` to utilize the correct parameter to allow sorting by exact match. The parameter is `isExactMatch` with a value of `True`. The argument used in `searchCVE` is still `exactMatch` with a value of `True`, NVDLib will now use the correct parameter when building the search query.

0.6.0 (2022-09-15)
-------------------
**Bugfixes**

- Updated `cve.py` to utilize the correct parameter to allow sorting of CVE collections by date. The parameter is `sortBy` with a value of `publishDate`. By @Smjert in https://github.com/vehemont/nvdlib/pull/8

0.5.9 (2022-09-03)
-------------------
**Bugfixes**

- Update `get.py` and `cve.py` to set the request encoding to `utf-8` to prevent any incorrect decoding of requests.

**Improvements**

- Update `cve.py` to add a request timeout of 30 seconds.  
- Updated `get.py` to enhance the `verbose=True` parameter to work with `searchCVE` and `searchCPE` and it will now print the parameters with each query to see what page a request is failing on, as utilizing `.raise_for_status()` to raise an HTTPError object if an error occurs during the request (such as 403 forbidden from too many requests).

0.5.8 (2022-07-19)
-------------------
**Bugfixes**

- Update get.py and cve.py by @GamehunterKaan in https://github.com/vehemont/nvdlib/pull/5
    - Removed exit() function that causes the program to abort. Modules shouldn't exit.
- Updated cve.py `searchCVE` doc string to include the `cweId` parameter.

**Improvements**

- Updated cve.py to include the `sortPublished` parameter that is supposed to sort a CVE collection by published date, rather than the default modified date. In my testing, I have not been able to get this parameter working as expected, and I receive no changes in response with or without the `sortOrder=publishedDate` parameter.  
I have decided to include the parameter since it is a valid API parameter. The NVD developer guide (https://nvd.nist.gov/developers/vulnerabilities) recommends to use this parameter to prevent missing CVEs when searching for large amounts of CVEs. 

0.5.7 (2022-05-18)
-------------------
**Bugfixes**

- Update get.py by @GamehunterKaan in https://github.com/vehemont/nvdlib/pull/4
    - Update request timeout in `get.py` to 30 seconds from 10 seconds because most api requests take longer than 10 seconds.
    - Update exception message from paramaters to str(paramaters) to prevent TypeErrors.

0.5.6 (2022-02-15)
-------------------
**Improvements**

- Added the ability to pass `datetime` objects to searchCVE and searchCPE as mod/pub dates instead of strings. Strings will still work at this time. 
```python
>>> end = datetime.datetime.now()
>>> start = end - datetime.timedelta(days=7)
>>> r = nvdlib.searchCVE(pubStartDate=start, pubEndDate=end, verbose=True)
Filter:
https://services.nvd.nist.gov/rest/json/cves/1.0?pubStartDate=2022-02-08T08:57:26:000 UTC-00:00&pubEndDate=2022-02-15T08:57:26:000 UTC-00:00
>>> len(r)
629
```
- Reworked __buildCVECall to utilize a dictionary to pass to __get using requests params argument, instead of building the string from scratch.
- Added a test framework (courtesy of @calve)


**Bugfixes**

- Immediately returned results if the total results from a search equals 20, instead of attempting to request a non-existant page.

0.5.5 (2022-02-10)
-------------------
**Improvements**

Updated CVE attribute `score` to include the severity, also rearranged the list to have the CVSS score version as the first element. This attribute is available on all CVEs and is a simpler way to obtain a score for a CVE without minding the version of the score.

Old:
```python
    >>> print(r[0].score)
    [8.8,'V3']
```

New:
```python
    >>> print(r[0].score)
    ['V3', 8.8, 'HIGH']
```
<br/>

0.5.4 (2022-01-24)
-------------------
**Bugfixes**
- Set score on CVEs with no score (due to awaiting analysis) to `None`. This allows for iterating on the score attribute without causing an attribute error.
```python
>>> import nvdlib
>>> r = nvdlib.searchCVE(keyword='log4j', key='xxxxxx-xxxx-xxxx-xxxxx-xxxxxxxx', limit=5)
>>> print([(x.id + ' ' + str(x.score[0])) for x in r])
['CVE-2022-23307 9.8', 'CVE-2021-44228 10.0', 'CVE-2022-21704 None', 'CVE-2021-4104 7.5', 'CVE-2022-23302 None']
```
<br/>

0.5.3 (2022-01-20)
-------------------
**Improvements**
- Added rate limiting to requests to accomadate the NIST NVD recommendations. <br>
Read more about it here: https://nvd.nist.gov/developers  
You can get an API key for free here: https://nvd.nist.gov/developers/request-an-api-key  
tl;dr - No API key = 10 requests per minute, or 6 seconds per request. API key = 100 requests per minute, or 0.6 seconds per request.
- A key parameter now exists in searchCVE, getCVe, and searchCPE to allow you to include your API key.  
```python
>>> r = getCVE('CVE-2021-30640', key='xxxx-xxxxxx-xxxxxxxx')  
```
- Remade the parameter building functions to move away from kwargs** and use keyword parameters instead. This removes the requirement for `cpe_dict=False` when making a search or get.
