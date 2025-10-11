resource "aws_vpc" "niz_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "niz-vpc" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.niz_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true
  tags = { Name = "niz-public-a" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.niz_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-northeast-2a"
  tags = { Name = "niz-private-a" }
}


resource "aws_subnet" "private_c" {
  vpc_id            = aws_vpc.niz_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "ap-northeast-2c"
  tags = { Name = "niz-private-c" }
}

resource "aws_internet_gateway" "niz_igw" {
  vpc_id = aws_vpc.niz_vpc.id
  tags   = { Name = "niz-igw" }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.niz_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.niz_igw.id
  }
  tags = { Name = "niz-public-rt" }
}

resource "aws_route_table_association" "public_a_assoc" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public_rt.id
}
