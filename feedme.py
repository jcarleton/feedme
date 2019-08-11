import json
import logging
import os
import re
import ssl
import sys
import urllib
from subprocess import call
from urllib.error import URLError
from flask import Flask, render_template, request
# import sqlalchemy
# from flask.ext.sqlalchemy import SQLAlchemy

# feedme v0.3 by Jesse Carleton
# a quick IP and domain lookup tool, intended for right click lookups in SIEM
# or IDS/IPS systems. can be used as a connector to other tools as well.


# to do
# SSL working properly
# templates, much pretty
# sql functionality


# debug logging
logger = logging.getLogger('feedme')


# kinda dangerous! allows you to trust any/all certificates! fix this soon!!!
ssl._create_default_https_context = ssl._create_unverified_context


app = Flask(__name__)


rfc1918 = re.compile("(^192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)|(^172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)|(^10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)")
ok_ip = re.compile("(^[2][0-5][0-5]|^[2][0-4][0-9]|^[1]{0,1}[0-9]{1,2})\.([0-2][0-5][0-5]|[2][0-4][0-9]|[1]{0,1}[0-9]{1,2})\.([0-2][0-5][0-5]|[2][0-4][0-9]|[1]{0,1}[0-9]{1,2})\.([0-2][0-5][0-5]|[2][0-4][0-9]|[1]{0,1}[0-9]{1,2})$")

# each caller will open the respective route query file as /tmp/whatever.query
# this will spawn a get request to whatever API is defined and return a
# /tmp/whatever.json for parsing in the routed function


def callopswat():
    ip = open('/tmp/opswat.query').read()
    url = 'https://api.metadefender.com/v1/scan/' + ip
    get = urllib.request.Request(url)
    get.add_header('User-Agent', "Fux0ring Gremlin!")
    get.add_header('apikey', 'PLACE_API_KEY_HERE')
    data = urllib.request.urlopen(get)
    logger.debug('OPSWAT call caught user request with validated IP: ' + ip + ' Querying...')
    mong = json.load(data)
    with open("/tmp/opswat.json", mode='w') as opswat_file:
        opswat_file.write(json.dumps(mong, indent=True, sort_keys=True))


def callrobtex():
    ip = open('/tmp/robtex.query').read()
    url = 'https://freeapi.robtex.com/ipquery/' + ip
    get = urllib.request.Request(url)
    get.add_header('User-Agent', "Fux0ring Gremlin!")
    data = urllib.request.urlopen(get)
    mong = json.load(data)
    with open("/tmp/robtex.json", mode='w') as robtex_file:
        robtex_file.write(json.dumps(mong, indent=True, sort_keys=True))


# ip_lookup route does just that, queries for an IP on 2 services right now
# Robtex and OPSWAT (which queries a bunch for you). Returns relevant threat
# intel, if available. Can add more services if needed. Uses files for debug
# info. Helpful for when things blow up and you dunno why.


@app.route('/ip_query/<ip>')
def ip_lookup(ip):
    try:
        if re.match(rfc1918, ip) is not None:
            logger.error('invalid IP address! %s selected!', ip)
            return 'Dawg, enter a proper IP address! ' + ip + ' is not a public IP (or maybe the attacker is already inside lol)'
        elif re.match(ok_ip, ip) is not None:
            try:
                with open("/tmp/opswat.query", mode='w') as opswat_query:
                    opswat_query.write(ip)
                    logger.debug('User query initiated. IP address %s is valid, proceeding...', ip)
                callopswat()
                opswat_json = json.loads(open('/tmp/opswat.json').read())
                with open("/tmp/robtex.query", mode='w') as robtex_query:
                    robtex_query.write(ip)
                callrobtex()
                logger.debug('Response obtained for IP: ' + ip + ' Parsing JSON...')
                robtex_json = json.loads(open('/tmp/robtex.json').read())

                # pull the json keys you want
                try:
                    ip_address = opswat_json["address"]
                except KeyError:
                    ip_address = "null"
                try:
                    detections = opswat_json["detected_by"]
                except KeyError:
                    detections = "null"
                try:
                    country_name = opswat_json["geo_info"]["country_name"]
                except KeyError:
                    country_name = "null"
                try:
                    scanned_time = opswat_json["start_time"]
                except KeyError:
                    scanned_time = "null"
                try:
                    o_source_one = opswat_json["scan_results"][0]["source"]
                except KeyError:
                    o_source_one = "null"
                try:
                    o_assessment_one_raw = opswat_json["scan_results"][0]["results"][0]["assessment"]
                    o_assessment_one = o_assessment_one_raw.split(', ', 1)[0]
                except KeyError:
                    o_assessment_one_raw = "null"
                try:
                    o_source_two = opswat_json["scan_results"][1]["source"]
                except KeyError:
                    o_source_two = "null"
                try:
                    o_assessment_two_raw = opswat_json["scan_results"][1]["results"][0]["assessment"]
                    o_assessment_two = o_assessment_two_raw.split(', ', 1)[0]
                except KeyError:
                    o_assessment_two_raw = "null"
                try:
                    o_source_three = opswat_json["scan_results"][2]["source"]
                except KeyError:
                    o_source_three = "null"
                try:
                    o_assessment_three_raw = opswat_json["scan_results"][2]["results"][0]["assessment"]
                    o_assessment_three = o_assessment_three_raw.split(', ', 1)[0]
                except KeyError:
                    o_assessment_three_raw = "null"
                try:
                    o_source_four = opswat_json["scan_results"][3]["source"]
                except KeyError:
                    o_source_four = "null"
                try:
                    o_assessment_four_raw = opswat_json["scan_results"][3]["results"][0]["assessment"]
                    o_assessment_four = o_assessment_four_raw.split(', ', 1)[0]
                except KeyError:
                    o_assessment_four_raw = "null"
                try:
                    o_source_five = opswat_json["scan_results"][4]["source"]
                except KeyError:
                    o_source_five = "null"
                try:
                    o_assessment_five_raw = opswat_json["scan_results"][4]["results"][0]["assessment"]
                    o_assessment_five = o_assessment_five_raw.split(', ', 1)[0]
                except KeyError:
                    o_assessment_five_raw = "null"
                try:
                    o_source_six = opswat_json["scan_results"][5]["source"]
                except KeyError:
                    o_source_six = "null"
                try:
                    o_assessment_six_raw = opswat_json["scan_results"][5]["results"][0]["assessment"]
                    o_assessment_six = o_assessment_six_raw.split(', ', 1)[0]
                except KeyError:
                    o_assessment_six_raw = "null"
                try:
                    o_source_seven = opswat_json["scan_results"][6]["source"]
                except KeyError:
                    o_source_seven = "null"
                try:
                    o_assessment_seven_raw = opswat_json["scan_results"][6]["results"][0]["assessment"]
                    o_assessment_seven = o_assessment_seven_raw.split(', ', 1)[0]
                except KeyError:
                    o_assessment_seven_raw = "null"

                try:
                    r_whoisdesc = robtex_json["whoisdesc"]
                except KeyError:
                    r_whoisdesc = "null"
                try:
                    r_asn = robtex_json["as"]
                except KeyError:
                    r_asn = "null"
                try:
                    r_asname = robtex_json["asname"]
                except KeyError:
                    r_asname = "null"
                try:
                    r_asdesc = robtex_json["asdesc"]
                except KeyError:
                    r_asdesc = "null"
                try:
                    r_bgproute = robtex_json["bgproute"]
                except KeyError:
                    r_bgproute = "null"
                try:
                    r_country = robtex_json["country"]
                except KeyError:
                    r_country = "null"

                # clean some stuff up, display something if there's zero hits
                if not country_name:
                    country_name = 'unknown country :: not assigned'
                if not detections:
                    detections = 'no detections by any '
                if not o_assessment_one:
                    o_assessment_one = 'unknown :: not indexed'
                if not o_assessment_two:
                    o_assessment_two = 'unknown :: not indexed'
                if not o_assessment_three:
                    o_assessment_three = 'unknown :: not indexed'
                if not o_assessment_four:
                    o_assessment_four = 'unknown :: not indexed'
                if not o_assessment_five:
                    o_assessment_five = 'unknown :: not indexed'
                if not o_assessment_six:
                    o_assessment_six = 'unknown :: not indexed'
                if not o_assessment_seven:
                    o_assessment_seven = 'unknown :: not indexed'
                if not r_asname:
                    r_asname = 'unknown :: not assigned'
                if not r_asdesc:
                    r_asdesc = 'unknown :: not assigned'

                # return that data, tidied up a little
                # this should be templated in a future version
                return 'IP Address: %s <br> Description: %s <br> ASN: %s <br> AS Name: %s <br> AS Desc: %s <br> BGP Route: %s <br><br> Country (by ASN): %s <br>'\
                       'Country (by other means): %s <br><br> Scan Initiated At: %s <br> Detected by: %s trackers <br><br> Source 1: %s <br> ' \
                       'Assessment: %s <br><br> Source 2: %s <br> Assessment: %s <br><br> Source 3: %s <br> Assessment: %s <br><br> Source 4: %s ' \
                       '<br> Assessment 4: %s <br><br> Source 5: %s <br> Assessment 5: %s <br><br> Source 6: %s <br> Assessment 6: %s <br><br>' \
                       'Source 7: %s <br> Assessment 7: %s ' % \
                       (
                       ip_address, r_whoisdesc, r_asn, r_asname, r_asdesc, r_bgproute, r_country, country_name, scanned_time, detections, o_source_one,
                       o_assessment_one, o_source_two, o_assessment_two, o_source_three, o_assessment_three, o_source_four, o_assessment_four,
                       o_source_five, o_assessment_five, o_source_six, o_assessment_six, o_source_seven, o_assessment_seven)


            except URLError as bad_hit:
                if hasattr(bad_hit, 'reason'):
                    logger.debug('Caught HTTP Error: ', bad_hit.reason)
                    return 'Caught an HTTP Error: ', bad_hit.reason
                elif hasattr(bad_hit, 'code'):
                    logger.debug('Caught HTTP Error Code: ', bad_hit.code)
                    return 'Caught HTTP Error Code: ', bad_hit.code
        else:
            logger.debug('Invalid target IP address (' + ip + ') selected!')
            return 'User specified IP Target is not valid! <br> You entered: ' + ip + '<br>Please enter a valid IP.'
    except re.error as bad_ip:
        logger.debug('IP Address is shit yo', bad_ip)
    logger.debug('query received for IP: %s', ip)
    logger.debug('Loading JSON... returning data to user!')


@app.route('/version/')
def version():
    return 'FeedMe v0.3'


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(message)s',
                        filename='feedme.log',
                        filemode='w')
    app.run()
