Release History
===============

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