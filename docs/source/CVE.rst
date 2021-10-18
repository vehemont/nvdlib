CVE
=====

.. _getCVE:

Single CVE
------------

**NVDLib** allows you to grab data on a single CVE if the CVE ID is known.
This is useful if you know the CVE but you need to know something about it such as the score,
publish date, etc. 

You can also use this to iterate through a list of CVE IDs if you have a list of known CVE IDs.

Begin by importing NVDLib:
   
   >>> import requests

Lets grab CVE-2017-0144.

   >>> r = nvdlib.getCVE('CVE-2017-0144')

From this point you are able to retrieve any information on the CVE.
Here is a method to print the version 3 CVSS severity.

   >>> print(r.v3severity)
   HIGH

Below are is all of the accessible variables within a CVE. Since these are assigned as is from the response of the aPI,
I recommend printing some of the values to get an idea of what they will return.

.. _cve:
.. autoclass:: nvdlib.classes.CVE
   :members:


Searching CVEs
------------

Searching for CVEs will return a list containing the objects of all of
the CVEs the search had found. 

.. note::
   Search has no limits by default, therefore if a search returns a 
   large amount of results, it may cause delays for the request to complete.

The NIST NVD API will block requests if they are sent too quickly in
an attempt to reduce the possibility of a DOS event. Therefore rate limiting
of the API is included in the library. It is miniscule rate limiting (usually
0.1 seconds), but when combined with thousands of requests, you may notice a
delay.

Example search for all vulnerabilities for Microsoft Exchange 2013, cumulative_update_11 and a limit of two:
   >>> r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_11:*:*:*:*:*:*', limit = 2)

Now we have the results of the search in a list containing each CVE. Each CVE use the same schema as 
the CVEs retrieved as used in :ref:`getCVE <cve>`.

   >>> type(r)
   <class 'list'>
   >>> for eachCVE in r:
   ... print(eachCVE.id)
   CVE-1999-1322
   CVE-2016-0032

.. autofunction:: nvdlib.cve.searchCVE


SearchCVE Examples:
------------

The arguments are not positional. SearchCVE will build the request based on what is passed to it. 
All of the parameters can be mixed together in any order.


Filter by publication end date, keyword, and version 3 severity of critical:

>>> r = nvdlib.searchCVE(pubEndDate = '2019-01-01 00:00', keyword = 'Microsoft Exchange', cvssV3Severity = 'Critical')

Filter for publications between 2019-06-02 and 2019-06-08:

>>> r = nvdlib.searchCVE(pubStartDate = '2019-06-08 00:00', pubEndDate = '2019-06-08 00:00')


Filter by CPE name and keyword with exact match enabled:

>>> r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_11:*:*:*:*:*:*', keyword = '1ArcServe', exactMatch = True)


Filter by CPE name, keyword, exact match enabled, and cpe_dict enabled:

>>> r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_11:*:*:*:*:*:*', keyword = '1ArcServe', exactMatch = True, cpe_dict = True)

Get the CVE IDs, score, and URL of a specific CPE name:

.. code-block:: python

   r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:5.0:-:*:*:*:*:*:*')
   for eachCVE in r:
      print(eachCVE.id, str(eachCVE.score[0]), eachCVE.url)