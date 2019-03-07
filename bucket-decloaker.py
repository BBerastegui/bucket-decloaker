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

    # Run generic checks
    cname_check(args.domain, bucket)
    url_check(args.domain, bucket)
    url_char_check(args.domain, bucket)

    # Run specific checks depending on the provider
    if bucket.provider is "aws":
        # Specific AWS checks
        torrent_check(args.domain, bucket)
    elif bucket.provider is "gcp":
        # Specific GCP checks
        signature_check(args.domain, bucket)
    elif bucket.provider is "azure":
        # Specific Azure checks
        print("[i] I need Azure checks...")
    else:
        print("Unknown provider / No provider found")

    # Output to a file specified in the output argument
    if args.output:
        with open('{}'.format(args.output), 'w') as outfile:
            json.dump(bucket.__dict__, outfile, sort_keys=True, indent=4)


# AWS, GCP
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
            # Check if the domain is directly pointing to a GCP bucket
            gcp_pattern = re.compile(".*\.storage\.googleapis\.com")
            if gcp_pattern.search(str(rdata.target)):
                print('[!] GCP bucket detected: {}'.format(domain))
                bucket.provider = "gcp"
                bucket.bucket_name = str(domain)
                return
    except Exception as e:
        print("[i] No CNAME record found.")
        return


# AWS, GCP
def url_check(domain, bucket):
    try:
        s3_url = 'https://{}.s3.amazonaws.com'.format(domain)
        r = requests.get(s3_url, verify=False)
        not_found_text = b'The specified bucket does not exist'
        if not_found_text not in r.content:
            print('[!] S3 bucket FQDN found in: {}.s3.amazonaws.com'.format(domain))
            print('[i] The match in the name of the domain and the bucket we found may be a lucky coincidence.')
            bucket.provider = "aws"
            bucket.bucket_name = domain
        gcp_url = 'https://storage.googleapis.com/{}'.format(domain)
        r = requests.get(gcp_url, verify=False)
        # Same not found text for GCP and AWS buckets
        not_found_text = b'The specified bucket does not exist'
        if not_found_text not in r.content:
            print('[!] GCP bucket found in: https://storage.googleapis.com/{}'.format(gcp_url))
            bucket.provider = "gcp"
            bucket.bucket_name = domain
    except Exception as e:
        print('[i] No bucket found in the preformatted urls for the services.')
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


# GCP
def signature_check(domain, bucket):
    try:
        r = requests.get('http://{}/1?GoogleAccessId=1&Expires=1&Signature=YnVja2V0LWRpc2Nsb3Nlcg=='.format(domain),
                         verify=False)
        # Check if the domain is directly pointing to an s3 bucket
        bucket_pattern = re.compile("/(.*)/1</StringToSign>")
        response_content = r.content.decode('utf-8')
        if bucket_pattern.search(r.content.decode('utf-8')) is not None:
            print('[!] GCP bucket detected with signature error: {}'.format(
                bucket_pattern.search(response_content).group(1)))
            bucket.bucket_name = bucket_pattern.search(response_content).group(1)
    except Exception as e:
        print('[i] No GCP bucket found with the signature "trick".')
        return


def torrent_check(domain, bucket):
    if bucket.bucket_name is not None:
        try:
            import urllib.request
            tmp_file_name, headers = urllib.request.urlretrieve(
                'http://{}.s3.amazonaws.com/index.html?torrent'.format(bucket.bucket_name))
            import torrent_parser as tp
            torrent_data = tp.parse_torrent_file(tmp_file_name)
            bucket.provider = "aws"
            bucket.bucket_name = torrent_data['info']['x-amz-bucket']
            return
        except Exception as e:
            print('[i] Error when trying to extract name from torrent.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decloak a domain containing an S3 bucket.')
    parser.add_argument('-d', '--domain', required=True, help='The domain containing a S3 bucket to be disclosed.')
    parser.add_argument('-o', '--output', required=False, help='Output file to write the results to.')

    args = parser.parse_args()

    main(args)
