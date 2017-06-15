# ThreatConnect Populator

[![Code Issues](https://www.quantifiedcode.com/api/v1/project/dd508e3927954df9b118ea9578c32b82/badge.svg)](https://www.quantifiedcode.com/app/project/dd508e3927954df9b118ea9578c32b82)

This script will create one of every possible object in ThreatConnect for testing or whatever other use you can find for it.

## Prerequisites

This script assumes that the following things are true of the owner in which you are creating the content:

- There are two security labels:
  - `TLP White`
  - `TLP Green`

## Installation

**Disclaimer:** This script was designed only for testing ThreatConnect. Your use of this script acknowledges that you accept any and all risk and unintended consequences of using the script.

In terminal/bash do the following:

```
# clone the repo.
git clone https://github.com/fhightower/threatconnect-populator.git

# move into the repo's directory
cd threatconnect-populator

# setup a tc.conf file
vi ./tc.conf  
# ^ paste your creds and config. settings into the file (see: https://docs.threatconnect.com/en/latest/python/python_sdk.html#configuration)
```

## Usage

The script expects one argument providing the owner into which the data will be created:

```
python tc_populate.py [-h] [-c] owner

Populate TC with test data

positional arguments:
  owner          owner to populate

optional arguments:
  -h, --help     show this help message and exit
  -c, --cleanup  delete the data created by this script
```

Simple example:

`python tc_populate.py "Example Community"`

The script works in python 2.x and 3.x .

## Cleanup

If you want to delete all of the test data created when running this script, you can do this by including -c when calling the script as shown below:

`python tc_populate.py -c "Example Community"`

This will create all of the object and then delete them if everything was created.

Alternatively, if you want to create the objects using this script and delete everything later, you can do this in the UI by finding the `TC Populator Example` tag in the browse screen (e.g. [https://app.threatconnect.com/auth/browse/index.xhtml?filters=&intelType=tags](https://app.threatconnect.com/auth/browse/index.xhtml?filters=&intelType=tags)) and deleting all of the objects associated with it.
