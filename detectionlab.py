#!/usr/bin/env python3

import requests, argparse, json, shutil, os, fnmatch, massedit, boto3

'''
ToDo:

* Don't use sed for variable replacement
* Support S3 Bucket Provisioning and Deprovisioning
* Automagically run box creation process

'''

# replace provision variables
def copy_templates():
    ''' 
    copy template files from ./Templates/ to ./Working/
    '''

    print("[+] Cloning ./Templates to ./Working directory")

    src_dirs = [ "Vagrant", "Packer", "Terraform"] 
    src_root = "./Templates/"
    dest_root = "./Working/"

    for src_dir in src_dirs:

        src_path = src_root + src_dir
        dest_path = dest_root + src_dir

        if os.path.exists(dest_path):
            print('[+] Directory %s exists, removing' %(dest_path)) 
            shutil.rmtree(dest_path)

        shutil.copytree(src_path, dest_path)


    src_files = [ "build.sh", "build.ps1"]

    for src_file in src_files:
        src_path = src_root + src_file
        shutil.copy(src_path, dest_root)

def walk_and_replace(find, replace):
    for path, dirs, files in os.walk(os.path.relpath("./Working/")):
        for filename in files:
            filepath = os.path.join(path, filename)
            filenames = [filepath]
            massedit.edit_files(filenames, ["re.sub('%s', '%s', line)" % (find, replace)], dry_run=False, output=os.devnull) 

def replace_provision_vars(config_json):

    print("[+] Replacing Provisioner Variables")
    
    config = config_json['provision']
    vars = ["PROVISION_USER", "PROVISION_PASSWORD", "PROVISION_DISPLAYNAME", "PROVISION_ORG_NAME",\
            "PROVISION_WIN10_ISO", "PROVISION_WIN2016_ISO", \
             "PROVISION_AWS_REGION", "PROVISION_AWS_PROFILE", "PROVISION_AWS_CREDENTIALS_FILE", "PROVISION_AWS_S3BUCKET",\
                 "PROVISION_SSH_KEY_NAME", "PROVISION_SSH_KEY_PUB", "PROVISION_SSH_KEY", "PROVISION_WHITELIST_IP"] 

    for var in vars: 
        walk_and_replace(var, config["%s" % var]) 

def replace_vagrant_vars(config_json):

    print("[+] Replacing Vagrant Variables")
    
    config = config_json['vagrant']
    vars = ["VAGRANT_WIN10_BOX", "VAGRANT_WIN2016_BOX", "VAGRANT_UBUNTU_BOX"] 

    for var in vars: 
        walk_and_replace(var, config["%s" % var]) 
 
def replace_domain_vars(config_json):

    print("[+] Replacing Domain Variables")
    
    config = config_json['domain']
    vars = ["DOMAIN_NAME", "DOMAIN_NETBIOS", "DOMAIN_DN"] 

    for var in vars: 
        walk_and_replace(var, config["%s" % var]) 

def replace_network_vars(config_json):

    print("[+] Replacing Network Variables")

    config = config_json['network']
    vars = ["VPC_IP_CIDR", "LAB_IP_CIDR", "LAB_IP_PREFIX", "LAB_NETMASK", "LAB_GATEWAY", "LAB_EXTDNS"] 

    for var in vars: 
        walk_and_replace(var, config["%s" % var]) 

def replace_host_ip_vars(config_json):


    print("[+] Replacing Host Variables")

    config = config_json['hosts']
    vars = ["DC_IP_ADDRESS", "WEF_IP_ADDRESS", "LOGGER_IP_ADDRESS", "WKSTN_IP_ADDRESS"]

    for var in vars: 
        walk_and_replace(var, config["%s" % var]) 

def replace_analystlogin_vars(config_json):

    print("[+] Replacing Analyst Login Variables")

    config = config_json['analyst']
    vars = ["KOLIDE_ADMIN_PASSWORD", "SPLUNK_ADMIN_PASSWORD", "GUACAMOLE_USERNAME", "GUACAMOLE_PASSWORD", "LOGGER_SSH_USERNAME", "LOGGER_SSH_PASSWORD"]

    for var in vars: 
        walk_and_replace(var, config["%s" % var]) 

def create_s3_bucket(bucket_name, aws_profile):

    session = boto3.Session(profile_name=aws_profile)
    s3 = session.client('s3')

    s3_create_response = s3.create_bucket(Bucket=bucket_name, ACL='private')


    s3_block_response = s3.put_public_access_block(
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        },
        Bucket=bucket_name
    )
    
    print("[+] Successfuly created S3 bucket %s" % bucket_name)

def delete_s3_bucket(bucket_name, aws_profile):
    session = boto3.Session(profile_name=aws_profile)
   
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket_name)
    bucket.objects.all().delete()

    s3 = session.client('s3')    
    s3_del_response = s3.delete_bucket(Bucket=bucket_name)

    print("[+] Successfuly deleted S3 bucket %s" % bucket_name)

def upload_ova_to_s3(bucket_name, aws_profile, local_file, s3_key):
    session = boto3.Session(profile_name=aws_profile)

    s3 = session.client('s3')

    s3_upload_response = s3.upload_file(local_file, bucket_name, s3_key)

def import_ami_from_s3():
    pass

def download_file(url, filename):
    local_filename = filename
    with requests.get(url, stream=True) as r:
        with open(local_filename, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

    return local_filename

def do_configure(config_json):

    copy_templates()
    replace_provision_vars(config_json)
    replace_vagrant_vars(config_json)
    replace_domain_vars(config_json)
    replace_network_vars(config_json)
    replace_host_ip_vars(config_json)
    replace_analystlogin_vars(config_json)

def do_download(dest_dir):

    windows_2016_iso = "https://software-download.microsoft.com/download/pr/Windows_Server_2016_Datacenter_EVAL_en-us_14393_refresh.ISO"
    windows_10_iso = "https://software-download.microsoft.com/download/pr/18362.30.190401-1528.19h1_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"

    print("[+] Downloading Windows 10 Enterprise Eval ISO")
    download_file(windows_10_iso, dest_dir + "/windows_10.iso")

    print("[+] Downloading Windows Server 2016 Eval ISO")
    download_file(windows_2016_iso, dest_dir + "/windows_2016.iso")

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="DetectionLab Deployment Helper")
    subparsers = parser.add_subparsers(dest='subcommand')
    
    iso_up_subparser = subparsers.add_parser('ova-to-s3')
    iso_up_subparser.add_argument("--config-file" , "-c", dest='config_file', default="config.json", help="Path to Config File, defaults to ./config.json" )
    iso_up_subparser.add_argument("--ova-path" , "-o", dest='local_file', help="Path to OVA file", required=True )
    iso_up_subparser.add_argument("--s3-key" , "-d", dest='s3_key', help="S3 Key Name", required=True )

    config_subparser = subparsers.add_parser('configure')
    config_subparser.add_argument("--config-file" , "-c", dest='config_file', default="config.json", help="Path to Config File, defaults to ./config.json" )

    s3_manage_subparser = subparsers.add_parser('s3-manage')
    s3_manage_subparser.add_argument("--config-file" , "-c", dest='config_file', default="config.json", help="Path to Config File, defaults to ./config.json" )
    s3_manage_group = s3_manage_subparser.add_mutually_exclusive_group(required=True)
    s3_manage_group.add_argument("--create" , action='store_true', help="Create S3 Bucket" )
    s3_manage_group.add_argument("--delete" , action='store_true',  help="Delete S3 Bucket and all contained objects" )

    iso_download_subparser = subparsers.add_parser('iso-download')
    iso_download_subparser.add_argument("--dest-dir" , "-d", dest='dest_dir', default="./iso/", help="Destination Directory, defaults to ./iso/" )

    subparsers.required = True

    args = vars(parser.parse_args())
    
    if args['subcommand'] == "ova-to-s3":

        config_file = open(args['config_file'], 'r') 
        config_json = json.load(config_file)

        bucket_name = config_json['provision']['PROVISION_AWS_S3BUCKET']
        aws_profile = config_json['provision']['PROVISION_AWS_PROFILE']

        local_file = args['local_file']
        s3_key = args['s3_key']

        upload_ova_to_s3(bucket_name, aws_profile, local_file, s3_key)

    elif args['subcommand'] == 'configure':
        config_file = open(args['config_file'], 'r') 
        config_json = json.load(config_file)
        do_configure(config_json)

    elif args['subcommand'] == 's3-manage':

        config_file = open(args['config_file'], 'r') 
        config_json = json.load(config_file)

        bucket_name = config_json['provision']['PROVISION_AWS_S3BUCKET']
        aws_profile = config_json['provision']['PROVISION_AWS_PROFILE']
        
        if args['create']:
            create_s3_bucket(bucket_name, aws_profile)

        elif args['delete']:
            delete_s3_bucket(bucket_name, aws_profile)

    elif args['subcommand'] == 'iso-download':
        do_download(args['dest_dir'])