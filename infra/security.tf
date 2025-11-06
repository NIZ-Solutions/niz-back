# NAT 인스턴스용 SG
resource "aws_security_group" "nat_sg" {
  name   = "niz-nat-sg"
  vpc_id = aws_vpc.niz_vpc.id

  # 외부 SSH 접속 허용
  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # 보안상 내 IP/32로 제한 권장
  }

  # 내부 트래픽 허용
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "niz-nat-sg" }
}

# 프라이빗 EC2용 SG
resource "aws_security_group" "niz_ec2_sg" {
  name   = "niz-ec2-sg"
  vpc_id = aws_vpc.niz_vpc.id

  # NAT 또는 내부에서만 SSH 가능
  ingress {
    description = "SSH Internal"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # NestJS 포트 내부 통신용
  ingress {
    description = "NestJS Internal"
    from_port   = 4000
    to_port     = 4000
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # PostgreSQL 내부 통신용
  ingress {
    description = "PostgreSQL Internal"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "niz-ec2-sg" }
}
