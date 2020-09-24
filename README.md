# GetAWSTargets
Tool to enumerate external facing AWS endpoints for vulnerability scanning and penetration testing.

Capable of checking every available region and assuming role into organization accounts.


# Usage
```
usage: GetAWSTargets.py [-h] [-p PROFILE] [-a] [-n] [-r REGIONS [REGIONS ...]] [-d] [-v] [-o {default,csv,json}] [-oJ OUTPUTJSON]

Get external facing AWS assets.

optional arguments:
  -h, --help            show this help message and exit
  -p PROFILE, --profile PROFILE
                        AWS profile to use.
  -a, --allaccounts     Enumerate and assume roles within organization accounts.
  -n, --norisky         Hide targets that are risky to scan (nano, micro, and m1.small instances).
  -r REGIONS [REGIONS ...], --regions REGIONS [REGIONS ...]
                        Enumerate specific AWS region(s).
  -d, --debug           Enable debug output.
  -v, --verbose         Enable verbose logging.
  -o {default,csv,json}, --output {default,csv,json}
                        Output format.
  -oJ OUTPUTJSON, --outputjson OUTPUTJSON
                        JSON output file.
```

# Example

```
$ python3 GetAWSTargets.py --profile staging --regions us-east-1 us-east-2 -v
[*]  Collecting regions.
[*]  Enumerating ec2 in region:  us-east-1
54.xxx.xxx.xxx
54.xxx.xxx.xxx
54.xxx.xxx.xxx
[*]  Enumerating ec2 in region:  us-east-2
[*]  Enumerating elb in region:  us-east-1
example1.us-east-1.elb.amazonaws.com
example2.us-east-1.elb.amazonaws.com
example3.us-east-1.elb.amazonaws.com
[*]  Enumerating elb in region:  us-east-2
[*]  Enumerating alb in region:  us-east-1
example1-alb.us-east-1.elb.amazonaws.com
example2-alb.us-east-1.elb.amazonaws.com
example3-alb.us-east-1.elb.amazonaws.com
[*]  Enumerating alb in region:  us-east-2
```