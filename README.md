
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


### Install
```bash
$ pip install nvdlib
```


### Demo
```python
>>> import nvdlib

# Perform the search with the known cpeName
>>> cves = nvdlib.searchCVE(cpeName='cpe:2.3:a:apache:tomcat:7.0.67:*:*:*:*:*:*:*', limit = 5)

# Pull CVE ID, score, and CVSS version of the score from the object.
>>> for eachCVE in cves:
>>>     print(eachCVE.id + ' - ' + eachCVE.score[0] + ' - ' + eachCVE.score[1])

CVE-2021-30640 - 6.5 - V3
CVE-2019-12418 - 7.0 - V3
CVE-2020-1938 - 9.8 - V3
CVE-2021-25329 - 7.0 - V3
CVE-2021-24122 - 5.9 - V3
```


### Documentation

https://nvdlib.com



#### More information

This is my first attempt at creating a library while utilizing all my Python experience from classes to functions.

For more information on the NIST NVD API for CPE and CVEs, see the documentation here: 
https://nvd.nist.gov/General/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement
