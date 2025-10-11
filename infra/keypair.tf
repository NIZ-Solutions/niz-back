resource "aws_key_pair" "niz_keypair" {
  key_name   = "niz-keypair"
  public_key = file("${path.module}/niz-keypair.pub")

  tags = {
    Name = "niz-keypair"
  }
}