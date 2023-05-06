"""
MISPy-OTX.py - This script takes the last year of OTX pulses you're subscribed to and imports them into a MISP Instance.
"""
import requests
from pymisp import PyMISP, MISPEvent, MISPObject
from pymisp import exceptions as pymisp_exceptions
from datetime import datetime
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='AlienVault OTX to MISP importer.')
    parser.add_argument('--update-timestamps', action='store_true',
                        help='Update timestamps of already imported events')
    return parser.parse_args()

# Configure API keys and endpoints
otx_api_key = 'yourotxkey123'
misp_api_key = 'yourmispkey123'
misp_url = 'https://your.misp.url

# Initialize MISP
misp = PyMISP(misp_url, misp_api_key, ssl=False)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Define a mapping between OTX types and MISP objects/attributes
otx_to_misp_mapping = {
    'IPv4': {'object': 'domain-ip', 'attribute': 'ip'},
    'IPv6': {'object': 'domain-ip', 'attribute': 'ip'},
    'domain': {'object': 'domain-ip', 'attribute': 'domain'},
    'hostname': {'object': 'domain-ip', 'attribute': 'hostname'},
    'email' : {'object': 'email', 'attribute': 'email'},
    'URL': {'object': 'url', 'attribute': 'url'},
    'URI': {'object': 'url', 'attribute': 'url'},
    'FileHash-MD5': {'object': 'file', 'attribute': 'md5'},
    'FileHash-SHA1': {'object': 'file', 'attribute': 'sha1'},
    'FileHash-SHA256': {'object': 'file', 'attribute': 'sha256'},
    'filename': {'object': 'file', 'attribute': 'filename'},
    'CVE': {'object': None, 'attribute': 'vulnerability'},
    # Add other mappings as needed
}
# Set the tag to add to the MISP event
misp_tag = 'Alienvault Import'

# Define a function to fetch all pulses you are subscribed to
def fetch_all_subscribed_pulses(limit=100, page=1):
    headers = {
        'X-OTX-API-KEY': otx_api_key,
    }
    url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
    params = {
        'limit': limit,
        'page': page
    }
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json().get('results', [])

# Define a function to create a MISP event from OTX data
def create_misp_event(otx_data):
    event = MISPEvent()
    event.info = f"{otx_data['name']}"
    event.distribution = 0  # Change this as needed
    event.threat_level_id = 2  # Change this as needed
    event.analysis = 0  # Change this as needed
    event.add_tag(misp_tag)

    # Convert OTX date format to MISP event date
    otx_date_format = '%Y-%m-%dT%H:%M:%S.%f'
    otx_created_date_str = otx_data['created']
    if '.' not in otx_created_date_str:
        otx_created_date_str += '.000000'
    otx_created_date = datetime.strptime(otx_created_date_str, otx_date_format)
    event.date = otx_created_date.strftime('%Y-%m-%d')

    return event

# Define a function to add OTX indicators to the MISP event
def add_otx_indicators_to_misp_event(event, otx_data):
    for indicator in otx_data['indicators']:
        indicator_type = indicator['type']
        if indicator_type in otx_to_misp_mapping:
            misp_object_type = otx_to_misp_mapping[indicator_type]['object']
            misp_attribute_type = otx_to_misp_mapping[indicator_type]['attribute']
            if misp_object_type and indicator_type != 'email': # Skip adding emails as objects
                misp_object = MISPObject(misp_object_type)
                try:
                    misp_object.add_attribute(misp_attribute_type, indicator['indicator'])
                except pymisp_exceptions.NewAttributeError:
                    print(f"Warning: The type of the attribute for '{indicator_type}' is required. Is the object template missing?")
                    continue
                event.add_object(misp_object)
            else:
                # Handle the 'vulnerability' attribute directly on the event
                event.add_attribute(misp_attribute_type, indicator['indicator'])
        else:
            print(f"Warning: Unsupported OTX indicator type '{indicator_type}'")
    return event

# Update the main function to process all subscribed pulses
from datetime import timedelta

def main(args):
    print("Starting the export process from AlienVault OTX...")
    limit = 100
    page = 1

    while True:
        print(f"Fetching page {page} of subscribed pulses...")
        subscribed_pulses = fetch_all_subscribed_pulses(limit=limit, page=page)

        if not subscribed_pulses:
            break

        for pulse in subscribed_pulses:
            pulse_title = f"AlienVault OTX data import: {pulse['name']}"

            # Convert OTX date format to datetime object
            otx_date_format = '%Y-%m-%dT%H:%M:%S.%f'
            otx_created_date_str = pulse['created']
            if '.' not in otx_created_date_str:
                otx_created_date_str += '.000000'
            otx_created_date = datetime.strptime(otx_created_date_str, otx_date_format)

            # Skip pulse if it's older than a year
            if datetime.utcnow() - otx_created_date > timedelta(days=365):
                print(f"Skipping pulse '{pulse['name']}' (ID: {pulse['id']}) - older than a year.")
                continue

            # Check if an event with the same title already exists in MISP
            existing_events = misp.search_index(eventinfo=pulse_title)
            if existing_events:
                event_id = existing_events[0]['id']
                if args.update_timestamps:
                    print(f"Updating date of event ID {event_id} for pulse '{pulse['name']}' (ID: {pulse['id']})")
                    event = misp.get_event(event_id)
                    updated_event = create_misp_event(pulse)

                    # Extract date from updated_event
                    updated_date = updated_event.date

                    # Update the existing event's "date" field with the new date
                    event['Event']['date'] = updated_date.strftime('%Y-%m-%d')
                    misp.update_event(event)
                else:
                    print(f"Skipping pulse '{pulse['name']}' (ID: {pulse['id']}) - already imported.")
                continue

            print(f"Processing OTX pulse: {pulse['name']} (ID: {pulse['id']})")
            event = create_misp_event(pulse)
            event = add_otx_indicators_to_misp_event(event, pulse)

            print("Importing MISP event into the MISP platform...")
            misp_response = misp.add_event(event)
            print(f"Event imported successfully. Event ID: {misp_response['Event']['id']}")

        page += 1


if __name__ == '__main__':
    args = parse_args()
    main(args)
