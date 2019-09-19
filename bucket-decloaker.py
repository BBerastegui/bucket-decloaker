#!/usr/bin/env python3

# S3 example: www.smalldatajournalism.com
# Cloudfront example: distribute.me.sel.sony.com
# GCP bucket permissions error example: audio-gc.spotify.com

import argparse
import dns.resolver
import re
import json
import tldextract

import requests
# Leave me alone, Python, I know what I'm doing:
# https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# https://stackoverflow.com/a/287944
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Bucket:
    def __init__(self):
        self.provider = None
        self.bucket_name = None
        self.load_balancer = None
        self.load_balancer_name = None
        # The attribute certain can be True/False if the check is not reliable
        self.certain = True


def main(args):
    bucket = Bucket()

    # Extract domain from url
    domain = ".".join(tldextract.extract(args.domain))

    # Run generic checks
    print("[i] Running generic and/or multiple vendor checks to find out provider...")
    cname_check(domain, bucket)
    http_headers(domain, bucket)
    url_check(domain, bucket)
    url_char_check(domain, bucket)

    # Run specific checks depending on the provider
    # If the provider is empty or the check is not certain, run all checks trying to find it
    if (bucket.provider in ["aws", None]) or (not bucket.certain):
        # Specific AWS checks
        print("[aws] Running aws specific checks...")
        soap_check(domain, bucket)
        name_in_listing(domain, bucket)
        torrent_check(domain, bucket)
    if (bucket.provider in ["gcp", None]) or (not bucket.certain):
        # Specific GCP checks
        print("[gcp] Running gcp specific checks...")
        signature_check(domain, bucket)
        permission_errors_check(domain, bucket)
    if (bucket.provider in ["azure", None]) or (not bucket.certain):
        # Specific Azure checks
        print("[azure] Running azure specific checks...")
        append_comp_parameter(domain, bucket)
        #print("[i] I need Azure checks...")

    # Now print the results nicely
    print_results(bucket)

    # Output to a file specified in the output argument
    if args.output:
        with open('{}'.format(args.output), 'w') as outfile:
            json.dump(bucket.__dict__, outfile, sort_keys=True, indent=4)


def print_results(bucket):
    if bucket.provider is not None:
        print(bcolors.OKGREEN + '[{}] Provider detected: {}'.format(bucket.provider, bucket.provider) + bcolors.ENDC)
    else:
        print(bcolors.WARNING + '[?] Provider not fingerprinted.' + bcolors.ENDC)

    if bucket.bucket_name is not None:
        print(bcolors.OKGREEN + '[{}] Bucket detected: {}'.format(bucket.provider, bucket.bucket_name) + bcolors.ENDC)
    else:
        print(bcolors.WARNING + '[?] Bucket name not found.' + bcolors.ENDC)

    if bucket.certain is False:
        print(bcolors.FAIL + '[?] The results are not certain (obtained using methods that do not guarantee that the '
                             'bucket behind the domain is the one you intend to find).' + bcolors.ENDC)
    # Finally, if nothing was fingerprinted
    if bucket.provider is None and bucket.bucket_name is None:
        print("[i] Unknown provider / No provider found")


# AWS, GCP
def cname_check(domain, bucket):
    try:
        answers = dns.resolver.query(domain, 'CNAME')
        for rdata in answers:
            # Remove trailing dot
            rdata.target = str(rdata.target).rstrip('.')
            # AWS
            # Check if the domain is served from Cloudfront
            if "cloudfront.net" in str(rdata.target):
                # In this case, we know that the provider is AWS
                bucket.provider = "aws"
                bucket.load_balancer = True
                bucket.load_balancer_name = str(rdata.target)
                return
            # Check if the domain is directly pointing to an s3 bucket
            s3_pattern = re.compile(".*s3.*\.amazonaws\.com")
            if s3_pattern.search(str(rdata.target)):
                bucket.provider = "aws"
                bucket.load_balancer = False
                bucket.load_balancer_name = str(rdata.target)
                return
            # GCP
            # Check if the domain is directly pointing to a GCP bucket
            gcp_pattern = re.compile(".*\.storage\.googleapis\.com")
            if gcp_pattern.search(str(rdata.target)):
                bucket.provider = "gcp"
                bucket.bucket_name = str(domain)
                return
            # AZURE
            # Check if the domain is served from Cloudfront
            if "azureedge.net" in str(rdata.target):
                # In this case, we know that the provider is AWS
                bucket.provider = "azure"
                bucket.load_balancer = True
                bucket.load_balancer_name = str(rdata.target)
                return
            # Check if the domain is pointing to an Azure load balancer storage
            azure_pattern = re.compile(".*\.(web|blob)\.core\.windows\.net")
            if azure_pattern.search(str(rdata.target)):
                bucket.provider = "azure"
                bucket.bucket_name = str(domain)
                return
    except Exception as e:
        print("[i] No CNAME record found.")
        pass


# AWS, GCP, Azure (TODO)
def http_headers(domain, bucket):
    # If 'Server: AmazonS3' in response headers, then AWS
    aws_s3_server_header = 'AmazonS3'
    try:
        r = requests.get('https://{}/'.format(domain), verify=False)
        server_header = r.headers.get('Server')
        if aws_s3_server_header in server_header:
            bucket.provider = "aws"

    except Exception as e:
        print('[i] No known clues found in HTTP headers.')
        pass


# AWS, GCP
def url_check(domain, bucket):
    try:
        # Same not found text for GCP and AWS buckets
        not_found_text = b'The specified bucket does not exist'

        # Check if the bucket exists in AWS S3
        s3_url = 'https://{}.s3.amazonaws.com'.format(domain)
        r = requests.get(s3_url, verify=False)
        if not_found_text not in r.content:
            bucket.provider = "aws"
            bucket.bucket_name = domain
            bucket.certain = False
            print('[!] S3 bucket detected (url API check): {}'.format(bucket.bucket_name))

        # Check if the bucket exists in the GCP Storage API
        gcp_url = 'https://storage.googleapis.com/{}'.format(domain)
        r = requests.get(gcp_url, verify=False)
        if not_found_text not in r.content:
            bucket.provider = "gcp"
            bucket.bucket_name = domain
            bucket.certain = False
    except Exception as e:
        print('[i] No bucket found in the preformatted urls for the services.')
        pass


# AWS
def url_char_check(domain, bucket):
    try:
        r = requests.get('https://{}/1%C0'.format(domain), verify=False)
        # Check if the domain is directly pointing to an s3 bucket
        bucket_pattern = re.compile("<URI>/(.*)/.*</URI>")
        response_content = r.content.decode('utf-8')
        if bucket_pattern.search(response_content) is not None:
            bucket.bucket_name = bucket_pattern.search(response_content).group(1)
            print('[!] S3 bucket detected (url %C0 character check): {}'.format(bucket.bucket_name))
    except Exception as e:
        print('[i] No S3 bucket found with url %C0 trick.')
        pass


# AWS
def soap_check(domain, bucket):
    try:
        # String to find in response if /soap is found
        is_soap_bucket = b'>Missing SOAPAction header<'

        # Perform request using POST method to /soap
        r = requests.post('https://{}/soap'.format(domain), verify=False)
        print(r.text)
        if is_soap_bucket in r.content:
            bucket.provider = "aws"
            print('[i] S3 bucket detected by querying /soap')
    except Exception as e:
        print('[i] Error when checking for /soap endpoint.')
        pass


# AWS
def name_in_listing(domain, bucket):
    try:
        r = requests.get('https://{}/'.format(domain), verify=False)
        # Check if the domain is directly pointing to an s3 bucket
        bucket_pattern = re.compile("<Name>(.*)</Name>")
        response_content = r.content.decode('utf-8')
        if bucket_pattern.search(response_content) is not None:
            bucket.bucket_name = bucket_pattern.search(response_content).group(1)
            print('[!] S3 bucket name detected (listing enabled, name in response): {}'.format(bucket.bucket_name))
    except Exception as e:
        print('[i] No S3 bucket found looking for name in listing.')
        pass


# AWS
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
            bucket.certain = True
            print('[!] AWS bucket found in the torrent file (torrent check): {}'.format(bucket.bucket_name))
        except Exception as e:
            print('[i] Error when trying to extract name from torrent.')
            pass


# GCP
# Look for iam.gserviceaccount.com in the response
# TODO - Check for permission errors in AWS in the same case
def permission_errors_check(domain, bucket):
    try:
        r = requests.get('https://{}/'.format(domain),
                         verify=False)
        # Check if the domain is returning a permission error for GCP buckets
        # The existence of this string in the response, means that it's a GCP bucket
        permissions_error_strings = ['.iam.gserviceaccount.com does not have ',
                                     'caller does not have storage.objects.list ']
        if any(error_string in r.content.decode('utf-8') for error_string in permissions_error_strings):
            bucket_pattern = re.compile("access to (.*).</Details></Error>")
            response_content = r.content.decode('utf-8')
            if bucket_pattern.search(response_content) is not None:
                bucket.provider = "gcp"
                bucket.bucket_name = bucket_pattern.search(response_content).group(1)
                print('[!] GCP bucket found in the response (permissions error): {}'.format(bucket.bucket_name))
        bucket.certain = True
    except Exception as e:
        print('[i] No GCP bucket found in the response (errors or such).')
        pass


# GCP
def signature_check(domain, bucket):
    try:
        r = requests.get('http://{}/1?GoogleAccessId=1&Expires=1&Signature=YnVja2V0LWRpc2Nsb3Nlcg=='.format(domain),
                         verify=False)
        # Check if the domain is directly pointing to an s3 bucket
        bucket_pattern = re.compile("/(.*)/1</StringToSign>")
        response_content = r.content.decode('utf-8')
        if bucket_pattern.search(response_content) is not None:
            bucket.bucket_name = bucket_pattern.search(response_content).group(1)
            print('[!] GCP bucket detected with signature error: {}'.format(bucket.bucket_name))
        bucket.certain = True
    except Exception as e:
        print('[i] No GCP bucket found with the signature "trick".')
        pass

# AZURE
def append_comp_parameter(domain, bucket):
    try:
        r = requests.get('http://{}/nonexistingasset000/?comp=list'.format(domain), verify=False)
        # Check if the response contains the appropriate error
        blob_pattern = re.compile("<UriPath>https?:\/\/(.*)\/nonexistingasset000\/\?comp=list<\/UriPath>")
        response_content = r.content.decode('utf-8')
        if blob_pattern.search(response_content) is not None:
            bucket.bucket_name = blob_pattern.search(response_content).group(1)
            print('[!] Azure blob storage detected by appending comp=list to a non existing resource: {}'.format(bucket.bucket_name))
        bucket.certain = True
    except Exception as e:
        print('[i] No Azure blob storage found by appending comp=list to a non existing resource.')
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decloak a domain potentially using a bucket or blob storage.')
    parser.add_argument('-d', '--domain', required=True, help='The domain containing a bucket or blob storage to be "discovered".')
    parser.add_argument('-o', '--output', required=False, help='Output file to write the results to.')

    args = parser.parse_args()

    main(args)
