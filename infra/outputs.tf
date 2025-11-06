output "nat_public_ip" {
  value = aws_eip.nat_eip.public_ip
}

output "vpc_id" {
  value = aws_vpc.niz_vpc.id
}