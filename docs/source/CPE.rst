CPE
=====

Search CPE
------------

Searching for CPEs is very similar to searching for CVEs albeit less parameters. 
CPE match strings are allowed, meaning if partial strings are known, you can search for all possible
CPE names.

Here is an example search with a keyword and a limit of 2 results then iterate through said CPE names.

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
    
    r = nvdlib.searchCPE(cpeMatchString = 'cpe:2.3:a:microsoft:exchange_server:2013:', cves = True)
    for eachCPE in r:
        for eachVuln in eachCPE.vulnerabilities:
            print(eachVuln)


Filter for CPE names modfied between 2019-01-01 and 2021-01-01 with the keyword of PHP.

.. note:: *len(r)* will return how many CPE entries were found in the result.

.. code-block:: python

    r = nvdlib.searchCPE(modStartDate = '2019-01-01 00:00', modEndDate = '2020-01-01 00:00', keyword = 'PHP')
    print(len(r))

    5992