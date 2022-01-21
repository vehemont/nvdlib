NVDLib: NIST National Vulnerability Database API Wrapper
===================================

.. image:: https://img.shields.io/github/license/bradleeriley/nvdlib
   :target: https://pypi.org/project/nvdlib/
   :alt: License Badge

.. image:: https://img.shields.io/badge/Python%203.8.3-https%3A%2F%2Fpypi.org%2Fproject%2Fnvdlib%2F-yellowgreen

.. image:: https://readthedocs.org/projects/nvdlib/badge/?version=latest
   :target: https://nvdlib.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

**NVDLib** is a Python API wrapper utilizing the REST API provided by NIST for the National Vulnerability Database (NVD).

-------------------

Demo::

   >>> import nvdlib
   >>> r = nvdlib.getCVE('CVE-2021-26855')
   >>> print(r.v3severity + ' - ' + str(r.v3score))
   CRITICAL - 9.8
   >>> print(r.cve.description.description_data[0].value)
   Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, 
   CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.
   >>> print(r.v3vector)
   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 

**NVDLib** is able to pull all data on known CVEs, search the NVD for CVEs 
or `Common Platform Enumeration (CPE) <https://nvd.nist.gov/products/cpe>`_ names.


Features:
----------------

* Pull data on individual CVEs:
 * CVE ID, description, reference links, CWE.
 * CPE applicability statements and optional CPE names.
 * CVSS severity scores.
 * CVE publication date.
 * CVE modified date.

* Search the NVD for CVEs by: 
 * Keywords
 * Publish or modification start/end dates
 * cweID
 * CVSS V2/V3, score, severity, or metrics.
 * CPE match string
 * CPE name.

* Search the NVD for CPE names by:
 * Modification start/End dates 
 * Keywords 
 * CPE match string. 
 * Dump data into objects to be accessible easily as class attributes. 


For more information on the NIST NVD API for CPE and CVEs, see the documentation here:
https://nvd.nist.gov/General/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement

.. note:: NVDLib version 0.5.3 now includes `NIST NVD rate limiting recommendations <https://nvd.nist.gov/developers>`_. Requests will now sleep for 6 seconds to 
   complete with no API key. Requests with an API key will sleep 0.6 seconds. 
   Get an API key here (free): https://nvd.nist.gov/developers/request-an-api-key

Navigation:
----------------

.. toctree::
   :maxdepth: 2

   started
   CVE
   CPE
   release
