# Specify the provider and access details
provider "aws" {
  shared_credentials_file = var.shared_credentials_file
  region                  = var.region
  profile                 = var.profile
}

# Create a VPC to launch our instances into
resource "aws_vpc" "default" {
  cidr_block = "VPC_IP_CIDR"
}

# Create an internet gateway to give our subnet access to the outside world
resource "aws_internet_gateway" "default" {
  vpc_id = aws_vpc.default.id
}

# Grant the VPC internet access on its main route table
resource "aws_route" "internet_access" {
  route_table_id         = aws_vpc.default.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.default.id
}

# Create a subnet to launch our instances into
resource "aws_subnet" "default" {
  vpc_id                  = aws_vpc.default.id
  cidr_block              = "LAB_IP_CIDR"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
}

# Adjust VPC DNS settings to not conflict with lab
resource "aws_vpc_dhcp_options" "default" {
  domain_name          = "DOMAIN_NAME"
  domain_name_servers  = concat([aws_instance.dc.private_ip], var.external_dns_servers)
  netbios_name_servers = [aws_instance.dc.private_ip]
}

resource "aws_vpc_dhcp_options_association" "default" {
  vpc_id          = aws_vpc.default.id
  dhcp_options_id = aws_vpc_dhcp_options.default.id
}

# Our default security group for the logger host
resource "aws_security_group" "logger" {
  name        = "logger_security_group"
  description = "DetectionLab: Security Group for the logger host"
  vpc_id      = aws_vpc.default.id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Splunk access
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Fleet access
  ingress {
    from_port   = 8412
    to_port     = 8412
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Guacamole Access
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }
  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  
  # Allow all traffic from the private subnet
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["LAB_IP_CIDR"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "windows" {
  name        = "windows_security_group"
  description = "DetectionLab: Security group for the Windows hosts"
  vpc_id      = aws_vpc.default.id

  # RDP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # WinRM
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Windows ATA
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Allow all traffic from the private subnet
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["LAB_IP_CIDR"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["LAB_IP_CIDR"]
  }
}

resource "aws_key_pair" "auth" {
  key_name   = var.public_key_name
  public_key = file(var.public_key_path)
}

resource "aws_instance" "logger" {
  instance_type = "t2.medium"
  ami           = coalesce(var.logger_ami, data.aws_ami.logger_ami.image_id)

  tags = {
    Name = "logger"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.logger.id]
  key_name               = aws_key_pair.auth.key_name
  private_ip             = "172.16.42.5"

  # Provision the AWS Ubuntu 16.04 AMI from scratch.
  provisioner "remote-exec" {
    inline = [
      "sudo add-apt-repository universe && sudo apt-get -qq update && sudo apt-get -qq install -y git",
      "sudo mkdir -p /opt/DetectionLab && sudo chmod 777 /opt/DetectionLab",
    ]

    connection {
      host        = coalesce(self.public_ip, self.private_ip)
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.private_key_path)
    }
  }

  # copy working directory
  provisioner "file" { 
    source      = "../../Working/"
    destination = "/opt/DetectionLab/"

    connection {
      host        = coalesce(self.public_ip, self.private_ip)
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.private_key_path)
    }

  }

  provisioner "remote-exec" {
    inline = [
      "echo 'logger' | sudo tee /etc/hostname && sudo hostnamectl set-hostname logger",
      "sudo adduser --disabled-password --gecos \"\" vagrant && echo 'vagrant:vagrant' | sudo chpasswd",
      "sudo mkdir /home/vagrant/.ssh && sudo cp /home/ubuntu/.ssh/authorized_keys /home/vagrant/.ssh/authorized_keys && sudo chown -R vagrant:vagrant /home/vagrant/.ssh",
      "sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config",
      "sudo service ssh restart",
      "echo 'vagrant    ALL=(ALL:ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
      "sudo sed -i 's/eth1/eth0/g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's/ETH1/ETH0/g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's#/usr/local/go/bin/go get -u#GOPATH=/root/go /usr/local/go/bin/go get -u#g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's#/vagrant/resources#/opt/DetectionLab/Vagrant/resources#g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo chmod +x /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo apt-get -qq update",
      "sudo /opt/DetectionLab/Vagrant/bootstrap.sh",
    ]

    connection {
      host        = coalesce(self.public_ip, self.private_ip)
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.private_key_path)
    }
  }

  root_block_device {
    delete_on_termination = true
    volume_size           = 64
  }
}

resource "aws_instance" "dc" {
  instance_type = "t2.medium"

  provisioner "remote-exec" {
    inline = ["choco install -force -y winpcap"]

    connection {
      type     = "winrm"
      user     = "vagrant"
      password = "vagrant"
      host     = coalesce(self.public_ip, self.private_ip)
    }
  }

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.dc_ami, data.aws_ami.dc_ami.image_id)

  tags = {
    Name = "dc.DOMAIN_NAME"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "DC_IP_ADDRESS"

  root_block_device {
    delete_on_termination = true
  }
}

resource "aws_instance" "wef" {
  instance_type = "t2.medium"

  provisioner "remote-exec" {
    inline = ["choco install -force -y winpcap"]

    connection {
      type     = "winrm"
      user     = "vagrant"
      password = "vagrant"
      host     = coalesce(self.public_ip, self.private_ip)
    }
  }

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.wef_ami, data.aws_ami.wef_ami.image_id)

  tags = {
    Name = "wef.DOMAIN_NAME"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "WEF_IP_ADDRESS"

  root_block_device {
    delete_on_termination = true
  }
}

resource "aws_instance" "win10" {
  instance_type = "t2.medium"

  provisioner "remote-exec" {
    inline = ["choco install -force -y winpcap"]

    connection {
      type     = "winrm"
      user     = "vagrant"
      password = "vagrant"
      host     = coalesce(self.public_ip, self.private_ip)
    }
  }

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.win10_ami, data.aws_ami.win10_ami.image_id)

  tags = {
    Name = "win10.DOMAIN_NAME"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "WKSTN_IP_ADDRESS"

  root_block_device {
    delete_on_termination = true
  }
}

