## Simple NIST NVD API wrapper library

<img src="docs/source/logo.png" width=300 style="padding-right:15px">

**NVDlib** is a Python library that allows you to interface with the [NIST National Vulnerability Database](https://nvd.nist.gov/) (NVD), pull vulnerabilities (CVEs), and [Common Platform Enumeration](https://nvd.nist.gov/products/cpe) (CPEs) into easily accessible objects.

![License](https://img.shields.io/github/license/bradleeriley/nvdlib) 
[![Written](https://img.shields.io/badge/Python%203.11.0-https%3A%2F%2Fpypi.org%2Fproject%2Fnvdlib%2F-yellowgreen)](https://pypi.org/project/nvdlib/)
[![Documentation Status](https://readthedocs.org/projects/nvdlib/badge/?version=latest)](https://nvdlib.readthedocs.io/en/latest/?badge=latest)

---

### Features

- Search the NVD for CVEs using all parameters allowed by the NVD API version 2. Including search criteria such as CVE publish and modification date, keywords, CVSS V2/V3/V4 severity or metrics, CPE name, CVE tags, and KEV catalog dates.
- Search CPE names by keywords, CPE match strings, or modification dates, and search CPE match strings.
- Retrieve details on individual CVEs, their relevant CPE names, CVSS 4.0 metrics, and more.
- Search the CVE change history and the organizations (sources) that provide NVD data.
- Get results as easily accessible objects, or pass `asDict=True` to get the plain dictionaries from the NVD API.
- Built in rate limiting according to [NIST NVD recommendations](https://nvd.nist.gov/developers/start-here). <br> Get an API key (https://nvd.nist.gov/developers/request-an-api-key) to allow for a delay argument to be passed. Otherwise it is 6 seconds between requests by default.

### Install
```bash
$ pip install nvdlib
```


### Demo
```python
>>> import nvdlib
>>> r = nvdlib.searchCVE(cveId='CVE-2021-26855')[0]
>>> print(r.v31severity + ' - ' + str(r.v31score))
CRITICAL - 9.1
>>> print(r.descriptions[0].value)
Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, 
CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.
>>> print(r.v31vector)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N 
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
https://nvd.nist.gov/developers

---

This product uses data from the NVD API but is not endorsed or certified by the NVD.
