# ThreatConnect Populator

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
python tc_populate.py [-h] owner
```

The script works in python 2.x and 3.x .

![Enjoy the process of creating... but not too much.](https://raw.githubusercontent.com/fhightower/threatconnect-populator/master/creating.png)
