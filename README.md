# DetectionLab 

A modified version of @clong's DetectionLab. All original credit to @clong <https://github.com/clong/DetectionLab>

Changes made to favor "build from scratch" and AWS deployment option

Changes: 
* Configurable credentials in Vagrant and Packer builds
* Configurable credentials for services (Splunk, Kolide)
* Configurable IP address ranges for Vagrant builds (Terraform as well with custom AMIs)
* Added dummy domain users and domain service accounts
* Added AD ACL attack paths and pwnable service accounts (ASREP-Roastable, Kerberoastable)


ToDo:
* Use Jinja2/ proper templating instead of hackish python find and replace
* Find a way to modify registry.pol files to replace hardcoded windomain.local domain

## Building from Scratch


Install requirements for the configuration script to run:

```
pip3 install -r requirements.txt
```

### Download Windows Enterprise Trial ISOs

Optional step if you prefer to have the ISOs local and not download them every time. If you do this, be sure to change the ISO paths in the config.json file to the file:/// path of the ISO.

Run the download script: 

```
./detectionlab.py iso-download -d ./iso
```

### Configure the environment

Copy the `config.json.template` file to `config.json` and change variables according to preference.

**DO NOT modify domain name variables... some GPO registry options have hardcoded domain names**

Run the configuration script.

```
./detectionlab.py configure -c config.json

```

### Build Box Images with Packer

Navigate to the `./Working/Packer` directory and execute packer commands to build the Vagrant box templates:

```
cd ./Working

# build Server 2016 Box
packer build --only=vmware-iso windows_2016.json 

# build Windows 10 Box
packer build --only=vmware-iso windows_10.json 

```

Import the Boxes to Vagrant:

Use the box names you set in the `config.json` file.

```
vagrant box add dl-win-10 windows_10_vmware.box
vagrant box add dl-win-2016 windows_2016_vmware.box
```

### Deploy lab with Vagrant

Navigate to `Working/Vagrant` directory and execute vagrant up.

```
cd ../Packer
vagrant up
```

This will build all the boxes at once. Another approach is to build them one at a time: 

```
vagrant up logger
vagrant up dc
vagrant up wef
vagrant up win10
```

### Install additional tools 

If additional installations can be automated either during the Packer or Vagrant build process, do that, but if not,
t his is a good place to stop and add anything additional to the lab boxes... EDR Agents, Microsoft Office, etc. 

Optionally, if you'd like to plan to export logger VM for local use, clear the Splunk index data with `/opt/splunk/bin/splunk clean eventdata`

### Export Vagrant Boxes to OVA

Export the boxes to OVA files so we can upload to S3 and deploy with Terraform magic.

1. Shut down the VMs in VirtualBox or VMWare. 
2. Snapshot the Windows VMs.
3. Export each VM as its own OVA file.

### Upload OVAs to S3 as AMIs.

1. Create the S3 bucket using the name provided in the `config.json` file:
    ```
    ./detectionlab.py s3-manage --create 
    ```

2. Upload the OVA images to the configured S3 bucket:
    ```
    ./detectionlab.py ova-to-s3 -o /path/to/win10.ova -d win10.ova
    ./detectionlab.py ova-to-s3 -o /path/to/dc.ova -d dc.ova
    ./detectionlab.py ova-to-s3 -o /path/to/wef.ova -d wef.ova
    ```
    
3. Create the vmimport role:

    ```
    aws --profile terraform iam create-role --role-name vmimport --assume-role-policy-document file:///path/to/DetectionLab/Working/Terraform/vm_import/trust-policy.json
    aws --profile terraform iam put-role-policy --role-name vmimport --policy-name vmimport --policy-document file:///path/to/DetectionLab/Working/Terraform/vm_import/role-policy.json
    ```

4. Import the OVAs
    ```
    aws --profile terraform ec2 import-image --description "dc" --license-type byol --disk-containers file:///path/to/DetectionLab/Working/Terraform/vm_import/dc.json
    aws --profile terraform ec2 import-image --description "wef" --license-type byol --disk-containers file:///path/to/DetectionLab/Working/Terraform/vm_import/wef.json
    aws --profile terraform ec2 import-image --description "win10" --license-type byol --disk-containers file:///path/to/DetectionLab/Working/Terraform/vm_import/win10.json
    ```

3. Follow the status and record AMI Ids: 

    ```
    aws --profile terraform ec2 describe-import-image-tasks --import-task-ids import-ami-xxxxxxx
    ```

4. Document AMI IDs

Document the AMI ID's and store them in the config.json file. 
Rerun `./detectionlab.py configure -c config.json` with the AMI ID's to push them to Terraform config files.

### Terraform!

## Out of Box Local (Vbox/VMWare) Deployment

Don't change any of the variables in the config template and deploy as usual.

## Out of Box AWS Deployment Deployment

Don't change any of the variables in the config template and deploy as usual.