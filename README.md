
<img src="docs/source/logo.png" width=300 align=left>

## Simple NIST NVD API wrapper library

![License](https://img.shields.io/github/license/bradleeriley/nvdlib) 
[![Written](https://img.shields.io/badge/Python%203.8.3-https%3A%2F%2Fpypi.org%2Fproject%2Fnvdlib%2F-yellowgreen)](https://pypi.org/project/nvdlib/)
[![Documentation Status](https://readthedocs.org/projects/nvdlib/badge/?version=latest)](https://nvdlib.readthedocs.io/en/latest/?badge=latest)

**NVDlib** is a Python library that allows you to interface with the [NIST National Vulnerability Database](https://nvd.nist.gov/) (NVD), pull vulnerabilities (CVEs), and [Common Platform Enumeration](https://nvd.nist.gov/products/cpe) (CPEs) into easily accessible objects.

<br/>

### Features

- Search the NVD for CVEs using all parameters allowed by the NVD API. Including search criteria such as CVE publish and modification date, keywords, severity, score, or CPE name.
- Search CPE names by keywords, CPE match strings, or modification dates. Then pull the CVE ID's that are relevant to those CPEs. 
- Retrieve details on individual CVEs, their relevant CPE names, and more.
- Built in rate limiting according to [NIST NVD recommendations](https://nvd.nist.gov/developers). <br> Get an API key (https://nvd.nist.gov/developers/request-an-api-key) to allow for 0.6 seconds between requests. Otherwise it is 6 seconds between requests.

### Install
```bash
$ pip install nvdlib
```


### Demo
```python
>>> import nvdlib
>>> r = nvdlib.getCVE('CVE-2021-26855')
>>> print(r.v3severity + ' - ' + str(r.v3score))
   CRITICAL - 9.8
>>> print(r.cve.description.description_data[0].value)
   Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, 
   CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.
>>> print(r.v3vector)
   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 
```


### Development

Run the tests with

```bash
$ pip install -e '.[dev]'
$ pytest
```

### Documentation

https://nvdlib.com



#### More information

This is my first attempt at creating a library while utilizing all my Python experience from classes to functions.

For more information on the NIST NVD API for CPE and CVEs, see the documentation here: 
https://nvd.nist.gov/General/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement
