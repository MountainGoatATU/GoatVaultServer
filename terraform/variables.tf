# ============================
# ENV VARIABLES
# ============================
variable "mongodb_url" {
  type        = string
  description = "The MongoDB connection URL"
  default     = "mongodb+srv://dev:1fQ5Tegmted0IxPp@dev.bhswmcl.mongodb.net/?retryWrites=true&w=majority&appName=dev"
}

variable "database_name" {
  type        = string
  description = "The name of the MongoDB database"
  default     = "goatvault"
}

variable "jwt_secret" {
  type        = string
  description = "Secret key for JWT signing"
  default     = "PB7KTN_edJEz5oUdhTRpaz2T_-SpZj_C5ZvD2AWPcPc"
}

variable "jwt_algorithm" {
  type        = string
  description = "Algorithm used for JWT signing"
  default     = "HS256"
}

variable "issuer" {
  type        = string
  description = "Issuer claim for JWT"
  default     = "GoatVaultServer"
}

variable "token_exp_hours" {
  type        = string
  description = "Token expiration time in hours"
  default     = "1"
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


variable "lambda_s3_key" {
  description = "S3 key for Lambda zip"
  type        = string
}

variable "lambda_source_code_hash" {
  description = "Base64-encoded SHA256 of Lambda zip"
  type        = string
}
