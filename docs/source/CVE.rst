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
   
   >>> import nvdlib

Lets grab CVE-2017-0144.

   >>> r = nvdlib.getCVE('CVE-2017-0144')

Example with an API key (insert your own API key).

   >>> r = nvdlib.getCVE('CVE-2017-0144', key='xxxxxx-xxxxx-xxxx-xxxx-xxxxxxxxxx')

.. note:: | Due to rate limiting restrictions by NIST, a request will take 6 seconds with no API key. 
    | Requests with an API key take 0.6 seconds per request.
    | Get a NIST NVD API key here (free): https://nvd.nist.gov/developers/request-an-api-key

From this point you are able to retrieve any information on the CVE.
Here is a method to print the version 3 CVSS severity.

   >>> print(r.v3severity)
   HIGH

If you just need a score and severity from a CVE, you can use the `score` attribute that contains a list. This exists 
on all CVE objects and will prefer version 3 scoring. If version 3 scoring does not exist, it will use version 2. If 
no scoring exists for the CVE, it will set all values to `None`. The first element is the CVSS version, then score, and severity.

   >>> print(r.score)   
   ['V3', 8.8, 'HIGH']

| 

.. autofunction:: nvdlib.cve.getCVE

Below are all of the accessible variables within a CVE. Since these are assigned as is from the response of the API,
I recommend printing some of the values to get an idea of what they will return. You can see what the JSON API response looks like and more details here
https://nvd.nist.gov/developers/vulnerabilities

.. _cve:
.. autoclass:: nvdlib.classes.CVE
   :members:

Searching CVEs
------------

Searching for CVEs will return a list containing the objects of all of
the CVEs the search had found. 

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
All of the parameters can be mixed together in any order. If a value is not passed to the function,
it is assumed to be false and will not be added to the filter.

.. note:: There is a maximum 120 day range when using date ranges. If searching publication or modified dates, start and end dates are required. A `datetime` object can also be used instead of a string.

Filter by publication start and end date, keyword, version 3 severity of critical, and an API key to allow for faster requests:

>>> r = nvdlib.searchCVE(pubStartDate = '2021-09-08 00:00', pubEndDate = '2021-12-01 00:00', keyword = 'Microsoft Exchange', cvssV3Severity = 'Critical', key='xxxxx-xxxxxx-xxxxxxx')

Get all CVEs in the last 7 days using a datetime object and use an API key.

>>> import datetime
>>> end = datetime.datetime.now()
>>> start = end - datetime.timedelta(days=7)
>>> r = nvdlib.searchCVE(pubStartDate=start, pubEndDate=end, key='xxxxx-xxxxxx-xxxxxxx')

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

Grab the CPE names that match a CVE.

.. note:: CPE names will only be returned if 'cpe_dict = True' is passed to the search as a parameter.

.. code-block:: python

   r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_11:*:*:*:*:*:*', keyword = '1ArcServe', exactMatch = True, cpe_dict = True)
   for eachCVE in r:
      config = eachCVE.configurations.nodes
      for eachNode in config:
         for eachCpe in eachNode.cpe_match:
               print(eachCpe.cpe23Uri)
