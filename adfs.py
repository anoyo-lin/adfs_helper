#!/usr/bin/python3
import pycurl
from urllib.parse import urlencode
import getpass
from io import BytesIO
import os, sys
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import base64
import boto3
import configparser
from os.path import expanduser
import json
import re
from urllib.parse import quote
def decrypt(index,section='gene'):
    #with open('cert.64', 'r') as s:
        #my_profile = s.readlines()
    #return base64.b64decode(my_profile[index]).decode('utf-8').rstrip() 
    config = configparser.ConfigParser()
    config.read('../.drn/credential.ini')
    if section=='gene':
        return base64.b64decode(config[section][index]).decode('utf-8').rstrip()
    else:
        return config[section][index].rstrip()
def auth(credential='AUTH'):
    if credential == 'TOKEN':
        passwd = getpass.getpass()
        passwd = decrypt('token_prefix') + passwd
        para={
                'username': decrypt('username'),
                'password': passwd,
                'vhost': 'standard'
                }
    elif credential == 'AUTH':
        para={
                'UserName': decrypt('corpuser'),
                'Password': decrypt('password'),
                'AuthMethod': 'FormsAuthentication'
                }
    return urlencode(para)
def proxy_auth():
    return quote(decrypt('username')) + ':' + quote(decrypt('password'))
class curl:
    def __init__(self, verbose=True):
        self.verbose = verbose 
    def request(self, url, output, content=None, proxy=None, method='GET'):
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        if self.verbose :
            c.setopt(pycurl.VERBOSE, 1)
        c.setopt(pycurl.COOKIEJAR, 'cookies')
        c.setopt(pycurl.COOKIEFILE, 'cookies')
#        c.setopt(pycurl.FAILONERROR, 1)

        if content and method == 'POST':
            c.setopt(pycurl.POST, 1)
            c.setopt(pycurl.POSTFIELDS, content)
        if content and method == 'PUT':
            c.setopt(pycurl.HTTPHEADER, ['Content-Type: application/json'])
            c.setopt(pycurl.CUSTOMREQUEST, 'PUT')
            c.setopt(pycurl.POSTFIELDS, content)
        if method == 'DELETE':
            c.setopt(pycurl.CUSTOMREQUEST, 'DELETE')
        
        if proxy :
            port = 8080
            if ':' in proxy:
                port = int(proxy.rsplit(':', 1)[1])
                proxy = proxy.rsplit(':', 1)[0]
            c.setopt(pycurl.PROXY, proxy)
            c.setopt(pycurl.PROXYPORT, port)
            c.setopt(pycurl.PROXYUSERPWD, "%s:%s" % (decrypt('username'),decrypt('password')))            
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        body = buffer.getvalue()
        buffer.close()
        dest = c.getinfo(pycurl.EFFECTIVE_URL)
        code = c.getinfo(pycurl.HTTP_CODE)
        c.close()
        return (body if output == 'body' else dest if output == 'dest' else code if output == 'code' else -1)
env = {
        'dev': ['aws_region_name', 'account_id']
        }
if len(sys.argv) == 2 and sys.argv[1] in env:
    region = env[sys.argv[1]][0]
else:
    print ('dev\tstage\tprodus\tprodeu\ncdev\tcstage\tcprod\nsdev\tslab\tsstage\tsprod\tsprod-dev\netest\telab\n')
    sys.exit(-1)
AWS_SP='https://[redacted]/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'
outputformat = 'json'
awsconfigfile =  '/.aws/credentials'
somc_proxy = 'http://[redacted]:8080'
os.environ['HTTP_PROXY'] = ''
os.environ['HTTPS_PROXY'] = ''

conn = curl(verbose=False) 
redir = conn.request(url=AWS_SP,output='dest',method='GET')
print (redir)
if redir == 'https://[redacted]/my.policy' :
    if os.path.isfile('cookies'):
        os.remove('cookies')
        conn.request(AWS_SP,'dest')
    redir_2 = conn.request(url=redir,output='dest',content=auth('TOKEN'),method='POST')
    saml_rep = conn.request(url=redir_2,output='body',content=auth('AUTH'),method='POST')
else:
    saml_rep = conn.request(url=redir,output='body',content=auth('AUTH'),method='POST')
del conn

soup = BeautifulSoup(saml_rep, 'html.parser')
for inputtag in soup.find_all('form'):
    if inputtag.get('name') == 'hiddenform' :
        sso = inputtag.get('action')
for inputtag in soup.find_all('input'):
    if inputtag.get('name') == 'SAMLResponse' :
        assertion = inputtag.get('value')
        
#def pretty_print_xml(xml):
#    proc = subprocess.Popen(
#        ['xmllint', '--format', '/dev/stdin'],
#        stdin=subprocess.PIPE,
#        stdout=subprocess.PIPE,
#    )
#    (output, error_output) = proc.communicate(xml);
#    return output

#soup = BeautifulSoup(base64.b64decode(assertion).decode('utf-8'), 'xml')
#print (soup.prettify())
#print (base64.b64decode(assertion).decode('utf-8'))

root = ET.fromstring(base64.b64decode(assertion))
awsroles = []
for attr in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if attr.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role' :
        for attr_val in attr.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(attr_val.text)
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if 'saml-provider' in chunks[0] :
        temp = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, temp)
        awsroles.remove(awsrole)
pattern = re.compile(env[sys.argv[1]][1])
for awsrole in awsroles:
    if pattern.search(awsrole.split(',')[0]):
        role_arn = awsrole.split(',')[0]
        principal_arn =  awsrole.split(',')[1]
#if len(awsroles) > 1:
#    i = 0
#    print ('Please choose one role to access: ')
#    for awsrole in awsroles:
#        print ('[', i, ']: ', awsrole.split(',')[0])
#        i += 1
#    print ('Selection: [ n ]')
#    selected = input()
#    if int(selected) > (len(awsroles) - 1) :
#        print ('Wrong Leading Number input, Quit!')
#        sys.exit(0)
#    role_arn = awsroles[int(selected)].split(',')[0]
#    principal_arn = awsroles[int(selected)].split(',')[1]
#else:
#    role_arn = awsroles[0].split(',')[0]
#    principal_arn = awsroles[0].split(',')[1]
#profile = role_arn.split('-')[1]
profile = sys.argv[1]
print (role_arn,principal_arn)
def check_status():
    conn = curl(verbose=False)
    try:
        conn.request(somc_proxy.rsplit(':',1)[0],output='code')
        return True
    except pycurl.error as err:
        return False
if check_status():
    os.environ['HTTP_PROXY'] = 'http://%s@[redacted]:8080' % proxy_auth()
    os.environ['HTTPS_PROXY'] = 'http://%s@[redacted]:8080' % proxy_auth()
client = boto3.client('sts')
response = client.assume_role_with_saml(
            RoleArn = role_arn,
            PrincipalArn = principal_arn,
            SAMLAssertion = assertion,
            Policy='{"Version":"2012-10-17","Statement":[{"Sid":"Stmt1","Effect":"Allow","Action":"*","Resource":"*"}]}',
            DurationSeconds=3600
            )
access_key = response.get('Credentials').get('AccessKeyId')
secret_key = response.get('Credentials').get('SecretAccessKey')
session_token = response.get('Credentials').get('SessionToken')
home = expanduser("~")
filename = home + awsconfigfile
config = configparser.ConfigParser()
config.read(filename)
if not config.has_section(profile):
    config.add_section(profile)

config.set(profile, 'output', outputformat)
config.set(profile, 'region', region)
config.set(profile, 'aws_access_key_id', access_key)
config.set(profile, 'aws_secret_access_key', secret_key)
config.set(profile, 'aws_session_token', session_token)
config.set('default', 'output', outputformat)
config.set('default', 'region', region)
config.set('default', 'aws_access_key_id', access_key)
config.set('default', 'aws_secret_access_key', secret_key)
config.set('default', 'aws_session_token', session_token)
with open(filename, 'w+') as configfile:
    config.write(configfile)

#print (decrypt('SwVer','drn'))
#print (decrypt('videoUrl','drn'))
#print (decrypt('SwId','drn'))
