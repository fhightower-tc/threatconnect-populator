#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('LICENSE') as license_file:
    license = license_file.read()

requirements = [
    'docopt>=0.6',
    'threatconnect'
]

setup(
    name='threatconnect_populator',
    version='0.1.0',
    description="Populate ThreatConnect with items.",
    author="Floyd Hightower",
    url='https://github.com/fhightower/threatconnect-populator',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'tc_populate=tc_populator.cli:main'
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    license=license,
    zip_safe=True,
    keywords='threatconnect populator',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ]
)
