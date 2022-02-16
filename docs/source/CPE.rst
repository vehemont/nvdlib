CPE
=====

Search CPE
------------

Searching for CPEs is similar to searching for CVEs albeit less parameters. 
CPE match strings are allowed, meaning if partial strings are known, you can search for all possible
CPE names. Like searching CVEs, the parameters are not positional.

Here is an example search with a keyword and a limit of 2 results then iterate through said CPE names.

.. note:: | Due to rate limiting restrictions by NIST, a request will take 6 seconds with no API key. 
    | Requests with an API key take 0.6 seconds per request.
    | Get a NIST NVD API key here (free): https://nvd.nist.gov/developers/request-an-api-key

.. code-block:: python

    import nvdlib
    
    r = nvdlib.searchCPE(keyword = 'Microsoft Exchange', limit = 2)
    for eachCPE in r:
        print(eachCPE.name)


    'cpe:2.3:a:microsoft:exchange_instant_messenger:-:*:*:*:*:*:*:*'
    'cpe:2.3:a:microsoft:msn_messenger_service_for_exchange:4.5:*:*:*:*:*:*:*'


.. autofunction:: nvdlib.cpe.searchCPE


.. autoclass:: nvdlib.classes.CPE

CPE Search Examples
------------

Filter for a partial cpeMatchString for Microsoft Exchange 2013, return all the vulnerabilities 
for said matching CPEs, and print their CVE IDs.

.. note:: CVEs returned using searchCPE do *not* contain details and are only the ID.

.. code-block:: python 
    
    r = nvdlib.searchCPE(cpeMatchString='cpe:2.3:a:microsoft:exchange_server:2013:', cves=True, key='xxxxxx-xxxxx-xxxx-xxxx-xxxxxxxxxx')
    for eachCPE in r:
        for eachVuln in eachCPE.vulnerabilities:
            print(eachVuln)


Filter for CPE names modfied between 2019-01-01 and 2021-01-01 with the keyword of PHP.

.. note:: There is a maximum 120 day range when using date ranges. If searching publication or modified dates, start and end dates are required. A `datetime` object can also be used instead of a string.
    
    | *len(r)* will return how many CPE (or CVE) entries were found in the result.

.. code-block:: python

    r = nvdlib.searchCPE(modStartDate='2019-01-01 00:00', modEndDate='2020-01-01 00:00', keyword='PHP')
    print(len(r))

    5992

Filter for all CPE names modified in the last 30 days using `datetime` objects.

>>> import datetime
>>> end = datetime.datetime.now()
>>> start = end - datetime.timedelta(days=30)
>>> r = nvdlib.searchCPE(modStartDate=start, modEndDate=end)