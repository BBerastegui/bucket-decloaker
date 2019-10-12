# bucket-decloaker
A simple tool to decloak/expose the bucket name behind a domain.

So... the idea here is to have a tool that will implement all the checks in these two resources:

- https://gist.github.com/fransr/a155e5bd7ab11c93923ec8ce788e3368
- https://medium.com/@localh0t/unveiling-amazon-s3-bucket-names-e1420ceaf4fa

And any other for AWS/Azure/GCP or any other similar provider.

# Usage

- Clone this repo.
- pip3 install -r requirements.txt
- Run.

```
$ python3 bucket-decloaker.py -d [REDACTED].com -o [REDACTED].json
[i] No CNAME record returned
[!] S3 bucket FQDN found in: [REDACTED].com.s3.amazonaws.com
[i] The match in the name of the domain and the bucket we found may be a lucky coincidence.
[i] No S3 bucket found with url %C0 trick. 
 $ cat [REDACTED].json
{
    "bucket_name": "[REDACTED].com",
    "cloudfront": null,
    "cloudfront_name": null,
    "provider": "aws"
}
```

# Info / Adding a check

The findings or useful information in the bucket are stored in the class "Bucket":

```
class Bucket:
    def __init__(self):
        self.provider = None
        self.bucket_name = None
        self.load_balancer = None
        self.load_balancer_name = None
        # The attribute certain can be True/False if the check is not reliable
        self.certain = True
```

The checks implemented will be run by passing the domain and an object of the class Bucket:

```
bucket = Bucket()
(...)
yourcustom_check(args.domain, bucket)
```

That custom check may change properties on the bucket that will reflect the information obtained from it. For example:

```
def yourcustom_check(domain, bucket):
    // Do your magic here
    bucket.provider = "gcp"
    bucket.bucket_name = "supersecretbucket-123"
    return
```

# To Do

- [x] Create a simple script that will try to guess the bucket from a domain name
- [ ] Implement GCP buckets checks
- [ ] Implement Azure buckets checks
- [ ] Add the method used to fingerprint the bucket in the results
- [ ] Implement @fransrosen's script checks (link above)
- [ ] Timeout for functions
- [ ] Add more files to be checked in the "torrent" trick (now only checking for `index.html?torrent`)
- [ ] Force "in code" the list of providers that can be set ["aws","gcp","azure"]

# Disclaimer

I suck at coding, so feel free to insult me or to completely refactor this piece of cr\*p.
