#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Script to create all available objects in ThreatConnect."""

import argparse
try:
    import ConfigParser
except:
    import configparser as ConfigParser
import sys

from threatconnect import ThreatConnect

OBJECTS = {
    'groups': {
        'adversary': "tc.adversaries()",
        'campaign': "tc.campaigns()",
        'document': "tc.documents()",
        'email': "tc.emails()",
        'incident': "tc.incidents()",
        'signature': "tc.signatures()",
        'threat': "tc.threats()",
    },
    'indicators': {
        'address': "0.0.0.0",
        'email_address': "example@example.com",
        'file': "8743b52063cd84097a65d1633f5c74f5",
        'host': "example.com",
        'url': "http://example.com/test/index.html",
    },
}


def init_parser():
    """Initialize the argument parser."""
    parser = argparse.ArgumentParser(description="Populate TC with test data")
    parser.add_argument(nargs=1, dest="owner", type=str,
                        help="owner to populate")

    return parser.parse_args()


def init_tc():
    """Initialize a TC instance."""
    tc = None

    config = ConfigParser.RawConfigParser()
    config.read("./tc.conf")

    try:
        api_access_id = config.get('threatconnect', 'api_access_id')
        api_secret_key = config.get('threatconnect', 'api_secret_key')
        api_default_org = config.get('threatconnect', 'api_default_org')
        api_base_url = config.get('threatconnect', 'api_base_url')
    except ConfigParser.NoOptionError:
        print('Could not read configuration file.')
        sys.exit(1)

    tc = ThreatConnect(api_access_id, api_secret_key, api_default_org,
                       api_base_url)

    return tc


def create_groups(tc, owner):
    """create_groups function."""
    for group in OBJECTS['groups']:
        group_type = None

        # instantiate object of a group type
        exec("group_type = OBJECTS['groups'][group]")
        # get the human readable name of the group type
        group_type_name = OBJECTS['groups'][group].split(".")[1][:-2]

        # create a new object of the current type
        new_object = group_type.add('{} Example'.format(group_type_name),
                                    owner)
        # add a description attribute
        new_object.add_attribute('Description', 'Description Example')
        # add a tag
        new_object.add_tag('Example')
        # add a security label
        new_object.set_security_label('TLP Green')

        try:
            # create the new object
            new_object.commit()
        except RuntimeError as e:
            print('Error: {0}'.format(e))
            sys.exit(1)


def create_indicators(tc, owner):
    """create_indicators function."""
    indicators = tc.indicators()

    for indicator_type in OBJECTS['indicators']:
        new_indicator = indicators.add(OBJECTS['indicators'][indicator_type],
                                       owner)
        new_indicator.set_confidence(75)
        new_indicator.set_rating(2.5)

        new_indicator.add_attribute('Description', 'Example Attribute')
        new_indicator.add_tag('Example')
        new_indicator.set_security_label('TLP White')

        try:
            new_indicator.commit()
        except RuntimeError as e:
            print('Error: {0}'.format(e))
            sys.exit(1)


def create_victim():
    """create_victim function."""
    raise NotImplementedError("Victim creation coming soon")


def create_task():
    """create_task function."""
    raise NotImplementedError("Task creation coming soon")


def main():
    """."""
    args = init_parser()

    # initialize TC instance
    tc = init_tc()

    # create group objects
    create_groups(tc, args.owner)

    # create indicator objects
    create_indicators(tc, args.owner)

    # create victim
    # create_victim()

    # create task
    # create_task()


if __name__ == '__main__':
    main()
