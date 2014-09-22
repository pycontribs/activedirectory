Welcome to Python ActiveDirectory documentation!
================================================

.. toctree::
   :maxdepth: 2

Installation
============

The easiest (and best) way to install activedirectory module is through `pip <http://www.pip-installer.org/>`_::

    $ pip install activedirectory

This will handle the client itself as well as the requirements.

If you're going to run the client standalone, we strongly recommend using a `virtualenv <http://www.virtualenv.org/>`_,
which pip can also set up for you::

    $ pip -E activedirectory install activedirectory
    $ workon activedirectory

Doing this creates a private Python "installation" that you can freely upgrade, degrade or break without putting
the critical components of your system at risk.

Source packages are also available at PyPI:

    http://pypi.python.org/pypi/activedirectory/

.. _Dependencies:


Quickstart
==========

Initialization
--------------

Everything goes through the ActiveDirectory object, so make one::

    from activedirectory import ActiveDirectory

    ad = ActiveDirectory("ldaps://ad.example.com:3269/dc=example,dc=com")

Authentication
--------------

Put credentials inside ~/.netrc file and they will be loaded from there.


API Documentation
=================


Changelog
=========

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
