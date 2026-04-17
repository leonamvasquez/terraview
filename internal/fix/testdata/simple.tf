resource "aws_s3_bucket" "logs" {
  bucket = "company-logs"
  acl    = "private"
}

resource "aws_s3_bucket" "data" {
  bucket = "company-data"
}

resource "aws_iam_role" "app" {
  name = "app-role"
}
