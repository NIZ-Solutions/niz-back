variable "db_password" { type = string }

resource "aws_security_group" "niz_rds_sg" {
  name   = "niz-rds-sg"
  vpc_id = aws_vpc.niz_vpc.id

  ingress {
    description = "Allow Postgres from VPC"
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

  tags = { Name = "niz-rds-sg" }
}

resource "aws_db_subnet_group" "niz_rds_subnet_group" {
  name       = "niz-rds-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_c.id]
  tags       = { Name = "niz-rds-subnet-group" }
}

resource "aws_db_instance" "niz_rds" {
  identifier              = "niz-db"
  engine                  = "postgres"
  engine_version          = "15"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "postgres"
  password                = var.db_password
  db_subnet_group_name    = aws_db_subnet_group.niz_rds_subnet_group.name
  skip_final_snapshot     = true
  publicly_accessible     = false
  vpc_security_group_ids  = [aws_security_group.niz_rds_sg.id]
  multi_az                = false
  tags = { Name = "niz-rds" }
}
