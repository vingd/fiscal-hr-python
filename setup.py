#!/usr/bin/env python

'''FiscalHr Setup'''

from distutils.core import setup

import fiscalhr

setup(
    name=fiscalhr.__title__,
    version=fiscalhr.__version__,
    author=fiscalhr.__author__,
    author_email=fiscalhr.__author_email__,
    url=fiscalhr.__url__,
    license=fiscalhr.__license__,
    description=fiscalhr.__doc__,
    long_description=open('README.rst').read(),
    packages=['fiscalhr'],
    package_data={
        'fiscalhr': [
            'fiskalizacija_service/certs/*.pem',
            'fiskalizacija_service/wsdl/*.wsdl',
            'fiskalizacija_service/schema/*.xsd',
        ],
    },
    dependency_links=['https://github.com/vingd/libxml2-python/archive/libxml2-python-2.7.8.zip'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines()],
    platforms=['OS Independent'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
