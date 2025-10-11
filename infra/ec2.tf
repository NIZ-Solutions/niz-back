resource "aws_security_group" "niz_ec2_sg" {
  name   = "niz-ec2-sg"
  vpc_id = aws_vpc.niz_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "niz-ec2-sg" }
}

resource "aws_instance" "niz_ec2" {
  ami                         = "ami-0c9c942bd7bf113a2"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public_a.id
  vpc_security_group_ids      = [aws_security_group.niz_ec2_sg.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.niz_keypair.key_name
  tags = { Name = "niz-ec2" }
}

resource "aws_eip" "niz_eip" {
  instance = aws_instance.niz_ec2.id
  domain   = "vpc"
  tags     = { Name = "niz-eip" }
}