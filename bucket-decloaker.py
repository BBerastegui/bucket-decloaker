#!/usr/bin/env python3

# S3 example: www.smalldatajournalism.com
# Cloudfront example: distribute.me.sel.sony.com

import argparse
import dns.resolver
import re
import json

import requests
# Leave me alone, Python, I know what I'm doing:
# https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Bucket:
    def __init__(self):
        self.provider = None
        self.bucket_name = None
        self.cloudfront = None
        self.cloudfront_name = None

def main(args):
    bucket = Bucket()

    # Run checks
    cname_check(args.domain, bucket)
    fqdn_check(args.domain, bucket)
    url_char_check(args.domain, bucket)
    torrent_check(args.domain, bucket)

    # Output to a file specified in the output argument
    if args.output:
        with open('{}'.format(args.output), 'w') as outfile:
            json.dump(bucket.__dict__, outfile, sort_keys=True, indent=4)

def cname_check(domain, bucket):
    try:
        answers = dns.resolver.query(domain, 'CNAME')
        for rdata in answers:
            # Check if the domain is server from Cloudfront
            if "cloudfront.net" in str(rdata.target):
                print('[i] Cloudfront detected: {}'.format(rdata.target))
                # In this case, we know that the provider is AWS
                bucket.provider = "aws"
                bucket.cloudfront = True
                bucket.cloudfront_name = str(rdata.target)
                return
            # Check if the domain is directly pointing to an s3 bucket
            s3_pattern = re.compile(".*s3.*\.amazonaws\.com")
            if s3_pattern.search(str(rdata.target)):
                print('[!] S3 bucket detected: {}'.format(rdata.target))
                bucket.provider = "aws"
                bucket.cloudfront = False
                bucket.bucket_name = str(rdata.target)
                return
    except Exception as e:
        print("[i] No CNAME record found.")
        return


def fqdn_check(domain, bucket):
    try:
        s3_fqdn = '{}.s3.amazonaws.com'.format(domain)
        r = requests.get('https://{}'.format(s3_fqdn), verify=False)
        not_found_text = b'The specified bucket does not exist'
        if not_found_text not in r.content:
            print('[!] S3 bucket FQDN found in: {}.s3.amazonaws.com'.format(domain))
            print('[i] The match in the name of the domain and the bucket we found may be a lucky coincidence.')
            bucket.provider = "aws"
            bucket.bucket_name = domain
    except Exception as e:
        print('[i] No S3 FQDN found with the domain name.')
        return


def url_char_check(domain, bucket):
    try:
        r = requests.get('https://{}/1%C0'.format(domain), verify=False)
        # Check if the domain is directly pointing to an s3 bucket
        bucket_pattern = re.compile("<URI>/(.*)/.*</URI>")
        if bucket_pattern.search(r.content) is not None:
            print('[!] S3 bucket detected: {}'.format(bucket_pattern.search(r.content).group(1)))
            bucket.bucket_name = bucket_pattern.search(r.content).group(1)
    except Exception as e:
        print('[i] No S3 bucket found with url %C0 trick.')
        return


def torrent_check(domain, bucket):
    if bucket.bucket_name is not None:
        import urllib.request
        tmp_file_name, headers = urllib.request.urlretrieve('http://{}.s3.amazonaws.com/index.html?torrent'.format(bucket.bucket_name))
        import torrent_parser as tp
        torrent_data = tp.parse_torrent_file(tmp_file_name)
        bucket.provider = "aws"
        bucket.bucket_name = torrent_data['info']['x-amz-bucket']
        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decloak a domain containing an S3 bucket.')
    parser.add_argument('-d', '--domain', required=True, help='The domain containing a S3 bucket to be disclosed.')
    parser.add_argument('-o', '--output', required=False, help='Output file to write the results to.')

    args = parser.parse_args()

    main(args)
