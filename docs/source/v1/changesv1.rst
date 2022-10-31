NVD API Version 2 changes
#########################

NVDLib version 0.7.0 and onward will be utilizing version 2 of the NVD API. All versions before 0.7.0 will utilize version 1.
Version 1 of the API is planned to be decomissioned around `September 2023 <https://nvd.nist.gov/General/News/change-timeline>`_. There
has been a lot of changes in version 2 of the API. This page will describe the changes seen within NVDLib, not neccesarily the new version of the API.

.. note:: 
    For a more in-depth look at what has changed in version 2 see the NVD page here: https://nvd.nist.gov/General/News/api-20-announcements


nvdlib.getCVE
-------------

* No longer exists. It is now bundled into :func:`nvdlib.searchCVE` with the arguement *cveId*.
* Keep in mind *searchCVE* will always return a list, so when using the argument *cveId* you must access the first element of the list.

>>> r = nvdlib.searchCVE(cveId='CVE-2021-26855')
>>> r[0].id
'CVE-2021-26855'

Or more conveniently:

>>> r = nvdlib.searchCVE(cveId='CVE-2021-26855')[0]
>>> r.id
'CVE-2021-26855'

|

nvdlib.searchCVE
----------------

* Arguments now match exactly stated in `NVD API documentation <https://nvd.nist.gov/developers/vulnerabilities>`_, instead of a shorthand. 
  For example, version 0.6.1 used the argument *keyword*, it is now *keywordSearch* in NVDLib 0.7.0. Changes include:
    * modStartDate -> lastModStartDate
    * modEndDate -> lastModEndDate
    * keyword -> keywordSearch
    * isExactMatch -> keywordExactMatch
    * cpeMatchString -> virtualMatchString
    * sortby -> No longer exists
    * includeMatchStringChange -> No longer exists
* Scores are now elaborated beyond 2 and 3 to include 3.1. \
  This means the *score* attribute on CVEs will now prefer 3.1 CVSS scoring over 3.0 and 2.0. 

>>> r[0].score
['V31', 9.8, 'CRITICAL']

* The CVE structure has changed, meaning information you were obtaining manually previously, may be in a new location. 
  I recommend looking at the new CVE page to get an idea of what it looks like now.
* New parameters! Check out :doc:`/v2/CVEv2`.

|

nvdlib.searchCPE
----------------

* *cves* parameter in :func:`nvdlib.searchCPE` no longer exists, as CPE searches cannot return CVEs anymore. 
* The same parameter changes in *searchCVE* are applies to :func:`nvdlib.searchCPE`.
* New parameters! Check out :doc:`/v2/CPEv2`.



