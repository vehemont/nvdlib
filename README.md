# NVDLib
## Simple NIST NVD API wrapper library

![License](https://img.shields.io/github/license/bradleeriley/nvdlib) 
[![Written](https://img.shields.io/badge/Python%203.8.3-https%3A%2F%2Fpypi.org%2Fproject%2Fnvdlib%2F-yellowgreen)](https://pypi.org/project/nvdlib/)


Nvdlib allows you to interface with the [NIST National Vulnerability Database](https://nvd.nist.gov/) and pull vulnerabilities (CVEs) and Common Platform Enumeration (CPEs) into easily accessible objects.


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
import nvdlib

# Perform the search with the known cpeName
cves = nvdlib.searchCVE(cpeName='cpe:2.3:a:apache:tomcat:7.0.67:*:*:*:*:*:*:*', limit = 5)

# Pull data from the CVE object.
for eachCVE in cves:
    print(eachCVE.id + ' - ' + eachCVE.score[0] + ' - ' + eachCVE.score[1])
```


### Documentation
Coming Soon TM



#### More information

This is my first attempt at creating a library while utilizing all my Python experience from classes to functions.