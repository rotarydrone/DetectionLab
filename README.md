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
* 

## Building from Scratch


Install requirements for the configuration script to run:

```
pip3 install -r requirements.txt
```

### Download Windows Enterprise Trial ISOs

Optional step if you prefer to have the ISOs local and not download them every time. If you do this, be sure to change the ISO paths in the config.json file to the file:/// path of the

Run the download script: 

```
./detectionlab.py --download-iso
```

### Configure the environment

Copy the `config.json.template` file to `config.json` and change variables according to preference.

**DO NOT modify domain name variables... some GPO registry options have hardcoded domain names**

Run the configuration script:

```
./configure.py -c config.json 2>/dev/null

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

### Export Vagrant Boxes to OVA

Export the boxes to OVA files so we can upload to S3 and deploy with Terraform magic.

Shut down the VMs in VirtualBox or VMWare. 
Snapshot the Windows VMs.
Export each VM as its own OVA file.

### Upload OVAs to S3 as AMIs.

To Do 

### Terraform!

## Out of Box Local (Vbox/VMWare) Deployment

Don't change any of the variables in the config template and deploy as usual.

## Out of Box AWS Deployment Deployment

Don't change any of the variables in the config template and deploy as usual.