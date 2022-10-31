CPE
###

Search CPE
------------

Searching for CPEs is similar to searching for CVEs albeit less parameters. 
CPE match strings are allowed, meaning if partial strings are known, you can search for all possible
CPE names. Like searching CVEs, the parameters are not positional.

.. note::
   Due to rate limiting restrictions by NVD, a request will take 6 seconds with no API key. Requests with an API key have the ability to define a `delay` argument. The delay argument must be a integer/float greater than 0.6 (seconds).
   
   Get a NIST NVD API key here (free): https://nvd.nist.gov/developers/request-an-api-key

|

Here is an example of a CPE search with a keyword and a limit of 2 results then iterate through said CPE names.

.. code-block:: python

    import nvdlib
    
    r = nvdlib.searchCPE(keywordSearch = 'Microsoft Exchange', limit = 2)
    for eachCPE in r:
        print(eachCPE.cpeName)


    'cpe:2.3:a:ca:unicenter_management_microsoft_exchange:-:*:*:*:*:*:*:*'
    'cpe:2.3:a:microsoft:exchange_instant_messenger:-:*:*:*:*:*:*:*''


.. autofunction:: nvdlib.cpe.searchCPE


.. autoclass:: nvdlib.classes.CPE

CPE Search Examples
-------------------

Filter for a partial cpeMatchString for Microsoft Exchange 2013, return all the vulnerabilities 
for said matching CPEs, and print their CVE IDs.

.. note:: The new NVD API version 2 (starting with NVDLib 0.7.0) cannot include CVE names in CPE searches anymore.

.. code-block:: python 
    
    r = nvdlib.searchCPE(cpeMatchString='cpe:2.3:a:microsoft:exchange_server:2013:', key='xxxxxx-xxxxx-xxxx-xxxx-xxxxxxxxxx', delay=6)
    for eachCPE in r:
        print(eachCPE.cpeName)


Filter for CPE names modfied between 2019-01-01 and 2021-01-01 with the keyword of PHP.

.. note:: There is a maximum 120 day range when using date ranges. If searching publication or modified dates, start and end dates are required. A `datetime` object can also be used instead of a string.
    
    | *len(r)* will return how many CPE (or CVE) entries were found in the result.

.. code-block:: python

    r = nvdlib.searchCPE(lastModStartDate='2020-01-01 00:00', lastModEndDate='2020-02-01 00:00', keywordSearch='PHP')
    print(len(r))

    1599

Filter for all CPE names modified in the last 30 days using `datetime` objects.

>>> import datetime
>>> end = datetime.datetime.now()
>>> start = end - datetime.timedelta(days=30)
>>> r = nvdlib.searchCPE(lastModStartDate=start, lastModEndDate=end)