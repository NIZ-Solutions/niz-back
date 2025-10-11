output "ec2_public_ip" {
  value = aws_eip.niz_eip.public_ip
}

output "rds_endpoint" {
  value = aws_db_instance.niz_rds.address
}

output "vpc_id" {
  value = aws_vpc.niz_vpc.id
}