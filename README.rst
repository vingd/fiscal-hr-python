===================
FiscalHr for Python
===================

FiscalHr is Python helper class for fiscalization in Croatia.

============
Installation
============

::

    pip install --process-dependency-links FiscalHr

or

::

    pip install https://github.com/vingd/libxml2-python/archive/libxml2-python-2.7.8.zip
    pip install FiscalHr

======================
Certificate conversion
======================

Example for `openssl`_: ::

    umask 0077
    openssl pkcs12 -in "FISKAL 1.P12" -out fiskal-1.pem


=============
Example Usage
=============

Send receipt
------------

.. code-block:: python

    from fiscalhr.fiscal import Fiscal

    fis = Fiscal('fiskal-1.pem', 'fiskal-1.pem', key_passphrase='some secret')

    now = fis.localtime_now()

    racun = fis.create('Racun')
    racun.Oib = '01234567890'
    racun.USustPdv = True
    racun.DatVrijeme = fis.format_time(now)
    racun.OznSlijed = 'P'
    racun.BrRac.BrOznRac = 7
    racun.BrRac.OznPosPr = 'PP-1'
    racun.BrRac.OznNapUr = 'NAP-4'

    porez = fis.create('Porez')
    porez.Stopa = fis.format_decimal(25)
    porez.Osnovica = fis.format_decimal(100)
    porez.Iznos = fis.format_decimal(25)

    racun.Pdv.Porez.append(porez)

    racun.IznosUkupno = fis.format_decimal(125)
    racun.NacinPlac = 'K'
    racun.OibOper = '01234567890'
    racun.NakDost = False

    racun.ZastKod = fis.generate_zki(racun)

    print racun.ZastKod

    response = fis.send('racuni', racun)

    print response


Register business premises
--------------------------

Example for registering internet shop, with no pass phrase on SSL key and test mode enabled:

.. code-block:: python

    from datetime import datetime
    from fiscalhr.fiscal import Fiscal

    fis = Fiscal('fiscal-key.pem', 'fiscal-cert.pem', test=True)

    pp = fis.create('PoslovniProstor')
    pp.Oib = '01234567890'
    pp.OznPoslProstora = '1'
    pp.RadnoVrijeme = 'non-stop'
    pp.DatumPocetkaPrimjene = fis.format_time(datetime(2013, 7, 1), 'Datum')

    adresa = fis.create('OstaliTipoviPP')
    adresa = "Internet trgovina"

    pp.AdresniPodatak.OstaliTipoviPP = adresa

    response = fis.send('poslovniProstor', pp, nosend=False)

    print response


Copyright and License
=====================

FiscalHr for Python is Copyright (c) 2013 Vingd, Inc. and licensed under
the MIT License.


.. _`openssl`: http://www.openssl.org/
