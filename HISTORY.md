Release History
===============

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