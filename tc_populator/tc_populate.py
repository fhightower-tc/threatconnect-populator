#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Script to create all available objects in ThreatConnect."""

try:
    import ConfigParser
except:
    import configparser as ConfigParser
import random
import sys

from threatconnect import ThreatConnect
from threatconnect.Config.IndicatorType import IndicatorType
from threatconnect.Config.ResourceType import ResourceType


TAG = "TC Populator Example"

objects = {
    "indicators": {
        "address": {
            "indicator": "1.1.1.1"
        },
        "asn": {
            "indicator": {
                "AS Number": "ASN22"
            },
            "type": IndicatorType.CUSTOM_INDICATORS
        },
        "cidrBlock": {
            "indicator": {
                "Block": "192.168.0.0/29"
            },
            "type": IndicatorType.CUSTOM_INDICATORS
        },
        "email_address": {
            "indicator": "john.galt@example.com"
        },
        "file": {
            "indicator": "8743b52063cd84097a65d1633f5c74f5"
        },
        "host": {
            "indicator": "example.com"
        },
        "mutex": {
            "indicator": {
                "Mutex": "ExAmPLe MUtEx"
            },
            "type": IndicatorType.CUSTOM_INDICATORS
        },
        "registryKey": {
            "indicator": {
                "Key Name": "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current",
                "Value Name": "Autopopulate",
                "Value Type": "REG_DWORD"
            },
            "type": IndicatorType.CUSTOM_INDICATORS
        },
        "url": {
            "indicator": "https://example.com/test/bingo.html"
        },
        "userAgent": {
            "indicator": {
                "User Agent String": "PeachWebKit/100.00 (KHTML, like Nothing Else)"
            },
            "type": IndicatorType.CUSTOM_INDICATORS
        },
    },
}


def init_tc(tc_conf_path):
    """Initialize a TC instance."""
    tc = None

    config = ConfigParser.RawConfigParser()
    config.read(tc_conf_path)

    try:
        api_access_id = config.get("threatconnect", "api_access_id")
        api_secret_key = config.get("threatconnect", "api_secret_key")
        api_default_org = config.get("threatconnect", "api_default_org")
        api_base_url = config.get("threatconnect", "api_base_url")
    except ConfigParser.NoOptionError:
        print("Could not read configuration file.")
        sys.exit(1)

    tc = ThreatConnect(api_access_id, api_secret_key, api_default_org,
                       api_base_url)

    return tc


def create_groups(tc, owner):
    """Create groups."""
    created_groups = list()

    # define the groups to be created
    objects['groups'] = {
        "adversary": tc.adversaries(),
        "campaign": tc.campaigns(),
        "document": tc.documents(),
        "email": tc.emails(),
        "incident": tc.incidents(),
        "signature": tc.signatures(),
        "threat": tc.threats(),
    }

    for group_type in objects["groups"]:
        print("Creating {} group".format(group_type))
        group_object = None

        # instantiate object of a group type
        group_object = objects["groups"][group_type]

        # create a new object of the current type
        new_object = group_object.add("{} Example".format(group_type.title()),
                                      owner)

        # add a description attribute
        new_object.add_attribute("Description", "Description Example")
        # add a source attribute
        new_object.add_attribute("Source", "Source Example")

        # add a security label
        new_object.set_security_label("TLP Green")
        # add a tag
        new_object.add_tag(TAG)

        """ SPECIFIC PROPERTIES """
        # document specific properties
        if group_type == "document":
            # add a file name
            new_object.set_file_name("test.txt")
            document_contents = "What hath God wrought?!?!"
            # upload some content into the Document
            new_object.upload(document_contents)
        # email specific properties
        elif group_type == "email":
            new_object.set_body("This is an email body.")
            new_object.set_header("This is an improper email header.")
            new_object.set_subject("This is an email subject.")
        # incident specific properties
        elif group_type == "incident":
            # add an event date
            new_object.set_event_date("2017-03-21T00:00:00Z")
        # signature specific properties
        elif group_type == "signature":
            new_object.set_file_name("bad_file.txt")
            # set the type of the Signature
            new_object.set_file_type("YARA")
            # set the contents of the signature
            new_object.set_file_text("rule example_sig : example")

        try:
            # create the new object
            new_object.commit()
        except RuntimeError as e:
            print("Error: {0}".format(e))
        else:
            created_groups.append({
                'id': new_object.id,
                'type': new_object.resource_type
            })

    return created_groups


def create_indicators(tc, owner, groups):
    """Create indicators."""
    indicators = tc.indicators()

    for indicator_type in objects["indicators"]:
        print("Creating {} indicator".format(indicator_type))
        if objects["indicators"][indicator_type].get("type"):
            # create a custom indicator
            new_indicator = indicators.add(objects["indicators"][indicator_type]["indicator"],
                                           owner=owner, type=objects["indicators"][indicator_type]["type"],
                                           api_entity=indicator_type)
        else:
            # create a standard indicator
            new_indicator = indicators.add(objects["indicators"][indicator_type]["indicator"], owner)

            # create association with one of the groups (currently, this only works for non-custom indicators)
            group_index = random.randint(0, len(groups) - 1)
            new_indicator.associate_group(groups[group_index]['type'], groups[group_index]['id'])
            # ^ once https://github.com/ThreatConnect-Inc/threatconnect-python/issues/49 is closed, the two lines above can be unindented so associations will be created with indicators of all types

        # set indicator"s ratings
        new_indicator.set_confidence(75)
        new_indicator.set_rating(2.5)

        # add a description attribute
        new_indicator.add_attribute("Description", "Description Example")
        # add a source attribute
        new_indicator.add_attribute("Source", "Source Example")

        # add a security label
        new_indicator.set_security_label("TLP White")
        # add a tag
        new_indicator.add_tag(TAG)
        # add a tag
        new_indicator.add_tag("False Positive")

        try:
            new_indicator.commit()
        except RuntimeError as e:
            print("Error: {0}".format(e))


def create_task(tc, owner):
    """Create Task."""
    # instantiate Tasks object
    tasks = tc.tasks()

    print("Creating task")

    # create a new Task in the given owner
    task = tasks.add("New Task", owner)

    # add a description attribute
    task.add_attribute("Description", "Description Example")
    # add a tag
    task.add_tag(TAG)
    # add a security label
    task.add_security_label("TLP Green")

    try:
        # create the Task
        task.commit()
    except RuntimeError as e:
        print("Error: {0}".format(e))


def create_victim(tc, owner):
    """Create Victim."""
    from threatconnect.VictimAssetObject import VictimAssetObject

    print("Creating victim")

    # instantiate Victims object
    victims = tc.victims()

    # create new Victim
    victim = victims.add("Books", owner)

    # set victim details (all are OPTIONAL)
    victim.set_nationality("Global")
    victim.set_org("Thinking")
    victim.set_suborg("Learning")
    victim.set_work_location("Everywhere")

    # add an email address asset to new victim (OPTIONAL)
    asset = VictimAssetObject(ResourceType.VICTIM_EMAIL_ADDRESSES)
    asset.set_address("libros@example.com")
    asset.set_address_type("Personal")
    victim.add_asset(asset)

    # add a network account asset to the new victim (OPTIONAL)
    asset = VictimAssetObject(ResourceType.VICTIM_NETWORK_ACCOUNTS)
    asset.set_account("book-are-us")
    asset.set_network("Active Directory")
    victim.add_asset(asset)

    # add a phone asset to the new victim (OPTIONAL)
    asset = VictimAssetObject(ResourceType.VICTIM_PHONES)
    asset.set_phone_type("1-800-867-5309")
    victim.add_asset(asset)

    # add a social network asset to the new victim (OPTIONAL)
    asset = VictimAssetObject(ResourceType.VICTIM_SOCIAL_NETWORKS)
    asset.set_account("@leer")
    asset.set_network("Twitter")
    victim.add_asset(asset)

    # add a website asset to the new victim (OPTIONAL)
    asset = VictimAssetObject(ResourceType.VICTIM_WEBSITES)
    asset.set_website("thinking.com")
    victim.add_asset(asset)

    # add a tag
    victim.add_tag(TAG)

    try:
        # create the Victim
        victim.commit()
    except RuntimeError as e:
        print("Error: {0}".format(e))


def cleanup(tc, owner):
    """Delete all of the data that was just created."""
    # delete all of the groups
    groups = tc.groups()

    # add filter(s) for groups
    filter1 = groups.add_filter()
    filter1.add_owner(owner)
    filter1.add_tag(TAG)

    try:
        groups.retrieve()
    except RuntimeError as e:
        print("Error: {0}".format(e))

    for group in groups:
        group.delete()

    # delete all of the indicators
    indicators = tc.indicators()

    # add filter(s) for indicators
    filter1 = indicators.add_filter()
    filter1.add_owner(owner)
    filter1.add_tag(TAG)

    try:
        indicators.retrieve()
    except RuntimeError as e:
        print("Error: {0}".format(e))

    for indicator in indicators:
        indicator.delete()

    # delete the task
    tasks = tc.tasks()

    # add filter(s) for tasks
    filter1 = tasks.add_filter()
    filter1.add_owner(owner)
    filter1.add_tag(TAG)

    try:
        tasks.retrieve()
    except RuntimeError as e:
        print("Error: {0}".format(e))

    for task in tasks:
        task.delete()

    # delete the victim
    victims = tc.victims()

    # add filter(s) for victims
    filter1 = victims.add_filter()
    filter1.add_owner(owner)
    filter1.add_tag(TAG)

    try:
        victims.retrieve()
    except RuntimeError as e:
        print("Error: {0}".format(e))

    for victim in victims:
        victim.delete()

    print("\nEverything is cleaned up. You're good to go!")


def main(args):
    """."""
    # initialize TC instance
    tc = init_tc(args['<path_to_api_conf_file>'])

    # create group objects
    created_groups = create_groups(tc, args['<owner>'])

    # create indicator objects
    create_indicators(tc, args['<owner>'], created_groups)

    # create task
    create_task(tc, args['<owner>'])

    # create victim
    create_victim(tc, args['<owner>'])

    if args['--cleanup']:
        # delete everything we just created
        cleanup(tc, args['<owner>'])


if __name__ == "__main__":
    # initialize values used in the script
    main()
