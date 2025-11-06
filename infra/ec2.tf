resource "aws_key_pair" "niz_keypair" {
  key_name   = "niz-keypair-251104"
  public_key = file("${path.module}/niz-keypair.pub")
  tags = { Name = "niz-keypair-251104" }
}

resource "aws_instance" "nat_instance" {
  ami                         = "ami-0c9c942bd7bf113a2"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public_a.id
  vpc_security_group_ids      = [aws_security_group.nat_sg.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.niz_keypair.key_name

  tags = { Name = "niz-nat-instance" }
}

resource "aws_eip" "nat_eip" {
  instance = aws_instance.nat_instance.id
  domain   = "vpc"
  tags     = { Name = "niz-nat-eip" }
}

resource "aws_network_interface" "nat_eni" {
  subnet_id         = aws_subnet.public_a.id
  security_groups   = [aws_security_group.nat_sg.id]
  source_dest_check = false
  tags = { Name = "niz-nat-eni" }
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.niz_vpc.id
  route {
    cidr_block  = "0.0.0.0/0"
    network_interface_id = aws_instance.nat_instance.primary_network_interface_id
  }
  tags = { Name = "niz-private-rt" }
}

resource "aws_route_table_association" "private_a_assoc" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private_rt.id
}

# 앱 서버 (프라이빗)
resource "aws_instance" "niz_ec2" {
  ami                  = "ami-0c9c942bd7bf113a2"
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.private_a.id
  vpc_security_group_ids = [aws_security_group.niz_ec2_sg.id]
  associate_public_ip_address = false
  key_name             = aws_key_pair.niz_keypair.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  user_data = <<-EOF
    #!/bin/bash
    set -e
    dnf update -y
    dnf install -y git jq awscli nodejs npm postgresql15 postgresql15-server
    /usr/pgsql-15/bin/postgresql-15-setup initdb
    systemctl enable postgresql-15
    systemctl start postgresql-15
    PASSWORD=$(aws ssm get-parameter --name "/niz/postgres_password" --with-decryption --region ap-northeast-2 --query "Parameter.Value" --output text)
    sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '$${PASSWORD}';"
    cd /home/ec2-user
    git clone https://github.com/NIZ-Solutions/niz-back.git
    cd niz-back
    npm install
    npm run build
    nohup npm run start:prod > /var/log/niz-back.log 2>&1 &
  EOF

  tags = { Name = "niz-ec2" }
}