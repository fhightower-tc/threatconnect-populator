# ThreatConnect Populator

This script will create one of every possible object in ThreatConnect for testing or whatever other use you can find for it.

## Prerequisites

This script assumes that the following things are true of the owner in which you are creating the content:

- There are two security labels:
  - `TLP White`
  - `TLP Green`

## Usage

The script expects one argument providing the owner into which the data will be created:

```
python tc_populate.py [-h] owner
```
