CVE
###

.. _cve:

Single CVE
**********

**NVDLib** allows you to grab data on a single CVE if the CVE ID is known.
This is useful if you know the CVE but you need to know something about it such as the score,
publish date, etc. 

You can also use this to iterate through a list of CVE IDs if you have a list of known CVE IDs.

Begin by importing NVDLib:
   
   >>> import nvdlib

Lets grab CVE-2017-0144.

   >>> r = nvdlib.searchCVE(cveId='CVE-2017-0144')

Example with an API key (insert your own API key).

   >>> r = nvdlib.searchCVE(cveId='CVE-2017-0144', key='xxxxxx-xxxxx-xxxx-xxxx-xxxxxxxxxx', delay=6)

.. note::
   Due to rate limiting restrictions by NVD, a request will take 6 seconds with no API key. Requests with an API key have the ability to define a `delay` argument. The delay argument must be a integer/float greater than or equal to 0.6 (seconds).
   
   Get a NIST NVD API key here (free): https://nvd.nist.gov/developers/request-an-api-key

:func:`nvdlib.searchCVE` will always return a `list`. Since we are obtaining a single CVE, there will always only be 1 element in the list
when using the `cveId` argument. From this point you are able to retrieve information on the CVE. Here is a method to print the version 3 CVSS severity on a single CVE after a search has been ran.

   >>> print(r[0].v31severity)
   HIGH

If you just need a score and severity from a CVE, you can use the `score` attribute that contains a list. This exists 
on all CVE objects and will prefer version 4.0 scoring. If version 4.0 scoring does not exist, it will use version 3.1 and so on. If 
no scoring exists for the CVE, it will set all values to `None`. The first element is the CVSS version, then score, and severity.

   >>> print(r[0].score)   
   ['V31', 8.8, 'HIGH']

.. note::
   CVSS 4.0 metrics do not match versions 2 and 3, and most CVEs still have no 4.0 score.

   `score` uses 4.0 whenever a 4.0 block exists, even when NVD's primary score is still 3.1. The 4.0 values come from the Primary 4.0 entry when one is marked. There is no exploitability or impact score. Threat and environmental scores are usually missing, and many other 4.0 fields are `NOT_DEFINED` or left unset.

   Do not combine `cvssV4Severity` or `cvssV4Metrics` with version 2 or 3 filters. NVD currently ignores the 4.0 filter and can return CVEs that have no 4.0 metrics.

| 

Below are all of the accessible variables within a CVE. Since these are assigned as is from the response of the API,
I recommend printing some of the values to get an idea of what they will return. You can see what the JSON API response looks like and more details here
https://nvd.nist.gov/developers/vulnerabilities

.. autoclass:: nvdlib.classes.CVE
   :members:

|

Searching CVEs
**************

Searching for CVEs will return a list containing the objects of all of
the CVEs the search had found. 

Example search for all vulnerabilities for Microsoft Exchange 2013, cumulative_update_11 and a limit of two:
   >>> r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_11:*:*:*:*:*:*', limit = 2)

Now we have the results of the search in a list containing each CVE.

   >>> type(r)
   <class 'list'>
   >>> for eachCVE in r:
   ...   print(eachCVE.id)
   CVE-1999-1322
   CVE-2016-0032

Below are all of the available parameters when searching for a collection of CVEs, along with what is expected to be passed to that parameter.

|

.. autofunction:: nvdlib.cve.searchCVE

|

In addition to `searchCVE` there is also `searchCVE_V2`. This function uses the same parameters as `searchCVE` except creates a generator. This is
useful if the search performed consumes a lot of data and there are memory constraints on the system. It will convert the CVE response one object at a time, 
instead of attempting to convert the entire data set into memory at once. Here is an example using `next()`.

>>> r = nvdlib.searchCVE_V2(keywordSearch='Microsoft Exchange 2010', limit=100)
>>> oneCVE = next(r)
>>> print(oneCVE.id)

SearchCVE Examples
******************

The arguments are not positional. SearchCVE will build the request based on what is passed to it. 
All of the parameters can be mixed together in any order. If a value is not passed to the function,
it is assumed to be false and will not be added to the filter. Pass `asDict=True` to get each CVE as the plain dictionary from NVD instead of an object.

.. note:: There is a maximum 120 day range when using date ranges. If searching publication or modified dates, start and end dates are required. A `datetime` object can also be used instead of a string.

Filter by publication start and end date, keyword, version 3 severity of critical, and an API key.

>>> r = nvdlib.searchCVE(pubStartDate = '2021-09-08 00:00', pubEndDate = '2021-12-01 00:00', keywordSearch = 'Microsoft Exchange', cvssV3Severity = 'Critical', key='xxxxx-xxxxxx-xxxxxxx', delay=6)

Version 4 filters work the same way. `cvssV4Severity` accepts `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. `cvssV4Metrics` takes a full or partial CVSS 4.0 vector.

>>> r = nvdlib.searchCVE(cvssV4Severity = 'HIGH', cvssV4Metrics = 'AV:N/AT:N')

Get several CVEs at once with `cveIds`, find disputed CVEs with `cveTag`, or find CVEs added to the KEV catalog in a date range.

>>> r = nvdlib.searchCVE(cveIds = 'CVE-2021-26855,CVE-2021-44228')
>>> r = nvdlib.searchCVE(cveTag = 'disputed', limit = 10)
>>> r = nvdlib.searchCVE(kevStartDate = '2024-01-01 00:00', kevEndDate = '2024-03-01 00:00')

Get all CVEs in the last 7 days using a datetime object and use an API key.

>>> import datetime
>>> end = datetime.datetime.now()
>>> start = end - datetime.timedelta(days=7)
>>> r = nvdlib.searchCVE(pubStartDate=start, pubEndDate=end, key='xxxxx-xxxxxx-xxxxxxx')

Filter for publications between 2019-06-02 and 2019-06-08:

>>> r = nvdlib.searchCVE(pubStartDate = '2019-06-08 00:00', pubEndDate = '2019-06-08 00:00')


Filter by CPE name and keyword with keyword exact match  enabled:

>>> r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_11:*:*:*:*:*:*', keywordSearch = '1ArcServe', keywordExactMatch = True)


Filter by CPE name, keyword, exact match enabled, and `isVulnerable` enabled:

>>> r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_11:*:*:*:*:*:*', keywordSearch = '1ArcServe', keywordExactMatch = True, isVulnerable = True)

Get the CVE IDs, score, and URL of all CVEs with a specific CPE name:

.. code-block:: python

   r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:5.0:-:*:*:*:*:*:*')
   for eachCVE in r:
      print(eachCVE.id, str(eachCVE.score[0]), eachCVE.url)

Grab the CPE names that match a CVE.

.. code-block:: python

   r = nvdlib.searchCVE(cpeName = 'cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_11:*:*:*:*:*:*')
   for eachCVE in r:
      print(eachCVE.cpe)


Search for 100 CVEs that have a source identifier of `cve@mitre.org`

>>> r = nvdlib.searchCVE(sourceIdentifier = 'cve@mitre.org', limit = 100)

CVE Change History
******************

`searchCVEHistory` returns the change events for CVEs, such as when NVD analyzed a CVE or when a CVSS score changed. 
`searchCVEHistory_V2` takes the same parameters and returns a generator.

>>> r = nvdlib.searchCVEHistory(cveId = 'CVE-2021-44228')
>>> for eachChange in r:
...   print(eachChange.created, eachChange.eventName)

.. autofunction:: nvdlib.history.searchCVEHistory

.. autoclass:: nvdlib.classes.CVEHistory

Sources
*******

`searchSource` returns the organizations that provide NVD data. Use it to look up a `sourceIdentifier` found on a CVE.
`searchSource_V2` takes the same parameters and returns a generator.

>>> r = nvdlib.searchSource(sourceIdentifier = 'cve@mitre.org')
>>> print(r[0].name)
MITRE

.. autofunction:: nvdlib.source.searchSource

.. autoclass:: nvdlib.classes.Source