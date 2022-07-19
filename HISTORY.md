Release History
===============
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
