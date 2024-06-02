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


In addition to `searchCPE` there is also `searchCPE_V2`. This function uses the same parameters as `searchCPE` except creates a generator. This is
useful if the search performed consumes a lot of data and there are memory constraints on the system. It will convert the CVE response one object at a time, 
instead of attempting to convert the entire data set into memory at once. Here is an example using `next()`.

>>> r = nvdlib.searchCPE_V2(keywordSearch='Microsoft Exchange 2010', limit=100)
>>> oneCVE = next(r)
>>> print(oneCVE.cpeName)

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


CPE Match Criteria API
------------

This will allow you to search for CPE Match Strings that you can then use in CPE searches. When you search using this API, it will return a list of `MatchStrings`. I hightly recommend
playing around with this API to get an understanding of how the responses work.

.. autofunction:: nvdlib.cpe.searchCPEmatch

.. autoclass:: nvdlib.classes.MatchString


CPE Match String Search Examples
-------------------


To obtain the CPE match strings for a single CVE and print the `matchCriteriaId` for each match.

.. code-block:: python 
    
    r = nvdlib.searchCPEmatch(cveId='CVE-2017-0144')
    for eachMatchString in r:
        print(eachMatchString.matchCriteriaId)

Within each `MatchString` element in the response there are the CPE names that match. Here is how we can print them.

.. code-block:: python 
    
    r = nvdlib.searchCPEmatch(cveId='CVE-2017-0144')
    for eachMatchString in r:
        for eachCPE in eachMatchString.matches:
            print(eachCPE.cpeName)

We can also filter down this result even further using the other arguments for the Match String API. Here is searching for all match strings for the CVE ID CVE-2017-0144,
along with only matchStrings that contain `cpe:2.3:o:microsoft:windows_server_2012:*`.

.. code-block:: python 
    
    r = nvdlib.searchCPEmatch(cveId='CVE-2017-0144', matchStringSearch='cpe:2.3:o:microsoft:windows_server_2012:*')
    for eachMatchString in r:
        for eachCPE in eachMatchString.matches:
            print(eachCPE.cpeName)

Not that this search would be very useful in reality, but we can also search for a specific `matchCriteriaId` on top of the other two filters. This will search for all 
CPE match strings for the CVE ID CVE-2017-0144, match strings that contain `cpe:2.3:o:microsoft:windows_server_2012:*`, and that have a `matchCriteriaId` UUID of 'AB506484-7F0C-46BF-8EA6-4FB5AF454CED'. 
Match criteria is a unique UUID to a match string, so searching for them will only yield a single result. Keep in mind `nvdlib.searchCPEmatch` is still returning a list, so even though there is 
only one element in the list, you must select element index `0` to access that data of that element.

.. code-block:: python 
    
    r = nvdlib.searchCPEmatch(cveId='CVE-2017-0144', matchStringSearch='cpe:2.3:o:microsoft:windows_server_2012:*', matchCriteriaId='AB506484-7F0C-46BF-8EA6-4FB5AF454CED')
    print(r[0].matchCriteriaId)
    'AB506484-7F0C-46BF-8EA6-4FB5AF454CED'