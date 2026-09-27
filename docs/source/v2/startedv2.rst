Getting started
###############

.. _Getting started:

Installation
------------

To use NVDLib, first install it using pip:

.. code-block:: console

   (.venv) $ pip install nvdlib

This will also install the requests package if you do not already have it installed.

Importing NVDLib
----------------

Before you begin utilizing NVDLib make sure you import the nvdlib.py module:

.. code-block:: python

   import nvdlib

Logging
-------

NVDLib uses the Python logging module. Request URLs are logged at the debug level, and errors are logged at the error level.
This replaces the old `verbose` parameter. The example below writes NVDLib and Requests logs to a file named "example_NVDLib.log".

.. code-block:: python

   import logging
   import nvdlib

   logging.basicConfig(filename='example_NVDLib.log', encoding='utf-8', level=logging.DEBUG)
   r = nvdlib.searchCVE(keywordSearch="Microsoft")