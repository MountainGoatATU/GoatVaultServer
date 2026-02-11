# ============================
# ENV VARIABLES
# ============================
variable "mongodb_url" {
  type        = string
  description = "The MongoDB connection URL"
}

variable "database_name" {
  type        = string
  description = "The name of the MongoDB database"
}

variable "jwt_secret" {
  type        = string
  description = "Secret key for JWT signing"
}

variable "jwt_algorithm" {
  type        = string
  description = "Algorithm used for JWT signing"
}

variable "issuer" {
  type        = string
  description = "Issuer claim for JWT"
}

variable "access_token_exp_minutes" {
  type        = string
  description = "Token expiration time in minutes"
}

variable "refresh_token_exp_days" {
  type        = string
  description = "Token expiration time in days"
}

# ============================
# TERRAFOAM VARIABLES
# ============================

variable "lambda_exec_role_name" {
  type        = string
  description = "Name of the IAM role for Lambda execution"
  default     = "goatvault-lambda-role"
}

variable "aws_lambda_function_name" {
  type        = string
  description = "Name of the AWS Lambda function"
  default     = "goatvault-lambda-function"
}

variable "api_gateway_name" {
  type        = string
  description = "Name of the API Gateway"
  default     = "goatvault-api"
}

variable "lambda_zip_path" {
  type        = string
  description = "Path to the local Lambda deployment zip file"
}
