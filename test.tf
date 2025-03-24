provider "aws" {
  region = "us-east-1"
  access_key = "hardcoded-access-key" # Hardcoded credentials - insecure!
  secret_key = "hardcoded-secret-key" # Hardcoded credentials - insecure!
}

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "insecure-terraform-bucket"
  acl    = "public-read" # Publicly accessible S3 bucket - insecure!

  versioning {
    enabled = false # Versioning disabled - insecure!
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Insecure security group with open rules"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Open to the world - insecure!
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"] # Open to the world - insecure!
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # Open egress - insecure!
  }
}

resource "aws_iam_user" "insecure_user" {
  name = "insecure-user"
  force_destroy = true # Automatically delete user resources without review - insecure!

  tags = {
    Environment = "test"
  }
}

resource "aws_iam_access_key" "insecure_access_key" {
  user = aws_iam_user.insecure_user.name
}

resource "aws_iam_policy" "insecure_policy" {
  name = "insecure-policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = "*", # Wildcard permissions - insecure!
        Effect   = "Allow",
        Resource = "*", # Wildcard resources - insecure!
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_insecure_policy" {
  user       = aws_iam_user.insecure_user.name
  policy_arn = aws_iam_policy.insecure_policy.arn
}

resource "aws_instance" "insecure_instance" {
  ami           = "ami-0c55b159cbfafe1f0" # Replace with an actual AMI ID
  instance_type = "t2.micro"
