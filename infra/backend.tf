terraform {
  backend "s3" {
    bucket         = "goatvault-terraform-state" # S3 bucket for storing Terraform state
    key            = "prod/terraform.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "terraform-locks" # DynamoDB table for state locking
    encrypt        = true
  }
}
