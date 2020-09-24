from __future__ import print_function
import boto3
import sys
import argparse
import json

# GLOBALS
args = None

risky_types = [
    't3.nano',
    't2.nano',
    't1.micro',
    'm1.small'
]

default_region = 'us-east-1'

"""
session = boto3.Session(
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
)
"""

def warn(*objs):
    print("[!] ", *objs, file=sys.stderr)

def error(*objs):
    print("[!] ", *objs)

def debug(*objs):
    if args.debug:
        #print("[*] ", *objs, file=sys.stderr)
        print("[*] ", *objs)

def info(*objs):
    if args.debug or args.verbose:
        #print("[*] ", *objs, file=sys.stderr)
        print("[*] ", *objs)


class GetAWSTargets():
    def __init__(self, profile=None):        
        self.session = boto3.session.Session(profile_name=profile)
        stsclient = self.session.client(service_name='sts', region_name=default_region)
        identity = stsclient.get_caller_identity()
        debug( identity )
        self.account = identity['Account']
        self.owner = identity['UserId']

        self.regions = None

        self.risky_instances = []
        self.accounts = [] # (id, owner)

    def get_accounts(self):
        #client = self.session.client('sts')
        info('Enumerating organization accounts')
        client = self.session.client('organizations')
        paginator = client.get_paginator('list_accounts')
        page_iterator = paginator.paginate()
        for page in page_iterator:        
            for acct in page['Accounts']:
                debug(acct) # print the account
                if acct['Status'] == 'ACTIVE':
                    info('Found account:',acct['Id'], acct['Email'])
                    self.accounts.append( (acct['Id'], acct['Email']) )

    def assume_role(self, acctid):
        try:
            info("Attempting to assume role for account:", acctid)
            stsclient = self.session.client(service_name='sts', region_name=default_region)
            member_creds = stsclient.assume_role(
                RoleArn="arn:aws:iam::{}:role/OrganizationAccountAccessRole".format(acctid),
                RoleSessionName=acctid
            )
            debug( member_creds )

            member_session = boto3.session.Session(
                aws_access_key_id=member_creds['Credentials']['AccessKeyId'],
                aws_secret_access_key=member_creds['Credentials']['SecretAccessKey'],
                aws_session_token=member_creds['Credentials']['SessionToken'],
                region_name=default_region
            )

            return member_session
        except Exception as e:
            info("Assume role failed for:", acctid)
            debug(e)
            return None # account may not have permission

    """
    GET ALL REGIONS
    """
    def get_regions(self):
        client = self.session.client('ec2', region_name=default_region)
        if self.regions:
            return self.regions
        else:
            info("Collecting regions.")
            resp = client.describe_regions()
            available_regions = [ x['RegionName'] for x in resp['Regions'] ]
            debug("Available regions:", available_regions)

            if args.regions:
                self.regions = []
                for region in args.regions:
                    if region in available_regions:
                        self.regions.append( region )
                    else:
                        error("Unsupported region provided:", region)
            else:
                self.regions = available_regions
            return self.regions

    """
    GET EC2 INSTANCES
    """
    def get_ec2(self, session=None, account=None, owner=None):
        if session is None:
            session = self.session

        for region in self.get_regions():
            info( "Enumerating ec2 in region: ", region )
            try:
                client = session.client(service_name='ec2', region_name=region)
                resp = client.describe_instances(
                    MaxResults=1000
                )
                #print( resp )

                if 'NextToken' in resp:
                    warn("WARNING: results were paginated but this script dont support that yet..")

                for reservation in resp['Reservations']:
                    for i in reservation['Instances']:
                        # i['KeyName']
                        #print(i['InstanceId'], i['InstanceType'], i['Placement']['AvailabilityZone'])
                        if i['InstanceType'].lower() in risky_types:
                            # save instance ID to compare against load balancer associations
                            self.risky_instances.append( i['InstanceId'] )

                        if 'PublicIpAddress' in i:
                            if i['InstanceType'].lower() in risky_types:
                                #self.output( i['PublicIpAddress'], True )
                                self.output(target=i['PublicIpAddress'], account=account, owner=owner, region=region, service='ec2', risky=True)
                            else:
                                #self.output( i['PublicIpAddress'] )
                                self.output(target=i['PublicIpAddress'], account=account, owner=owner, region=region, service='ec2', risky=False)
                            #print('-->', i['PublicIpAddress'])
            except Exception as e:
                debug(e)
                pass # in case there are explicit deny for a region

    """
    GET LOAD BALANCERS
    """
    def get_elb(self, session=None, account=None, owner=None):
        if session is None:
            session = self.session

        for region in self.get_regions():
            info( "Enumerating elb in region: ", region )
            try:
                # ELB v1
                client = session.client(service_name='elb', region_name=region)
                resp = client.describe_load_balancers()

                #print( resp )

                for e in resp['LoadBalancerDescriptions']:
                    risky_elb = False
                    for i in e['Instances']:
                        if i['InstanceId'] in self.risky_instances:
                            risky_elb = True
                        if risky_elb:
                            #self.risky_targets.append( e['DNSName'])
                            #self.output( e['DNSName'], True )
                            self.output(target=e['DNSName'], account=account, owner=owner, region=region, service='elb', risky=True)
                        else:
                            #self.ok_targets.append( e['DNSName'] )
                            #self.output( e['DNSName'] )
                            self.output(target=e['DNSName'], account=account, owner=owner, region=region, service='elb', risky=False)

            except Exception as e:
                debug(e)
                pass # in case there are explicit deny for a region

    """
    GET ELBv2 (ALB) LOAD BALANCERS
    """
    def get_alb(self, session=None, account=None, owner=None):
        if session is None:
            session = self.session

        for region in self.get_regions():
            info( "Enumerating alb in region: ", region )
            try:
                client = session.client(service_name='elbv2', region_name=region)
                resp = client.describe_load_balancers()
                for e in resp['LoadBalancers']:
                    # TODO .. have to pull listener and target groups ...
                    #self.output( e['DNSName'] )
                    self.output(target=e['DNSName'], account=account, owner=owner, region=region, service='elbv2', risky=False)

            except Exception as e:
                debug(e)
                pass # in case there are explicit deny for a region

    """
    role : Default None. If supplied, script will attempt to assume role.
    """
    def get_all_targets(self):
        self.get_ec2()
        self.get_elb()
        self.get_alb()

        if args.allaccounts:
            self.get_accounts()
            for acctid, acctemail in self.accounts:
                info('Enumerating targets in member account: ', acctid, acctemail)
                member_session = self.assume_role( acctid )
                if member_session:
                    self.get_ec2(session=member_session, account=acctid, owner=acctemail)
                    self.get_elb(session=member_session, account=acctid, owner=acctemail)
                    self.get_alb(session=member_session, account=acctid, owner=acctemail)



        """
        GET ELASTIC IPS WITH ALLOCATIONS
        """
        """
        resp = client.describe_addresses(
            MaxResults=1000
        )
        for address in resp["Addresses"]:
            if "PublicIp" in address:
        """

        """
        TODO LAMBDA
        """

    # self.output(target='', account=account, owner=owner, region=region, service='alb', risky=False)
    def output(self, target, region, service, account=None, owner=None, risky=False):
        if risky:
            if args.norisky:
                return
        if account is None:
            account = self.account
        if owner is None:
            owner = self.owner

        if args.output == "default":
            print( target )
        elif args.output == "json":
            print( json.dumps({
                'account' : account,
                'owner' : owner,
                'region' : region,
                'service' : service,
                'target': target
            }))
        elif args.output == "csv":
            print( "{account}, {owner}, {region}, {service}, {target}".format(account=account, owner=owner, region=region, service=service, target=target) )

        if args.outputjson:
            args.outputjson.write( json.dumps( { 
                'account' : account,
                'owner' : owner,
                'region' : region,
                'service' : service,
                'target': target
            } ))

        sys.stdout.flush()


def main(argv):
    parser = argparse.ArgumentParser(description='Get external facing AWS assets.')
    parser.add_argument("-p", "--profile", help="AWS profile to use.")#, required=True)
    parser.add_argument("-a", "--allaccounts", action='store_true', help="Enumerate and assume roles within organization accounts.")
    parser.add_argument('-n', '--norisky', action='store_true', help='Hide targets that are risky to scan (nano, micro, and m1.small instances).')
    parser.add_argument('-r', '--regions', nargs='+', required=False, help='Enumerate specific AWS region(s).')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging.')
    # TODO - restric regions / services
    parser.add_argument('-o', '--output', default="default", type=str, required=False, choices=['default', 'csv', 'json'], help='Output format.')
    parser.add_argument('-oJ', '--outputjson', type=argparse.FileType('w'), help='JSON output file.')

    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)
    try:
        global args
        args = parser.parse_args() 
        
        awst = GetAWSTargets(profile=args.profile)
        awst.get_all_targets()
        #awst.get_accounts()

    except IOError as err: 
        print(str(type(err)) + " : " + str(err))
        parser.print_help()
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
