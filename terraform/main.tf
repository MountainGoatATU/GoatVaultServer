# ============================
# IAM ROLE FOR LAMBDA
# ============================
resource "aws_iam_role" "lambda_exec_role" {
  name = var.lambda_exec_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ==================================
# VPC + Subnets + Internet/NAT
# ==================================

resource "aws_vpc" "lambda_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "lambda-vpc" }
}

# Public Subnet (for NAT)
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.lambda_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "eu-west-1a"
  tags                    = { Name = "lambda-public-subnet" }
}

# Private Subnet (for Lambda)
resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.lambda_vpc.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "eu-west-1a"
  tags                    = { Name = "lambda-private-subnet" }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lambda_vpc.id
  tags   = { Name = "lambda-igw" }
}

# Route Table for Public Subnet
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lambda_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "public-rt" }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# NAT Gateway (in Public Subnet)
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags = {
    Name = "nat-eip"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet.id
  depends_on    = [aws_internet_gateway.igw]
}

# Route Table for Private Subnet (outbound via NAT)
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.lambda_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = { Name = "private-rt" }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.private_rt.id
}

# ============================
# LAMBDA AND API GATEWAY
# ============================

resource "aws_security_group" "lambda_sg" {
  name   = "lambda-sg"
  vpc_id = aws_vpc.lambda_vpc.id

  egress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # allow outbound to internet, but atlas only allows ip of NAT
  }

  tags = { Name = "lambda-sg" }
}

# One Lambda
resource "aws_lambda_function" "api" {
  function_name = var.aws_lambda_function_name
  role          = aws_iam_role.lambda_exec_role.arn
  runtime       = "python3.11"
  handler       = "app.lambda_handler.handler"

  timeout     = 30
  memory_size = 512

  // Uncomment below to use local zip file for deployment
  // Comment out the 'filename' and 'source_code_hash' in 'aws_lambda_function' resource to use Pipeline deployment
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  environment {
    variables = {
      MONGODB_URL     = var.mongodb_url
      DATABASE_NAME   = var.database_name
      JWT_SECRET      = var.jwt_secret
      JWT_ALGORITHM   = var.jwt_algorithm
      ISSUER          = var.issuer
      TOKEN_EXP_HOURS = var.token_exp_hours
    }
  }

  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
}

# API Gateway
resource "aws_apigatewayv2_api" "goatvault_api" {
  name          = var.api_gateway_name
  protocol_type = "HTTP"
}

# Connect API Gateway to Lambda
resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id                 = aws_apigatewayv2_api.goatvault_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "proxy" {
  api_id    = aws_apigatewayv2_api.goatvault_api.id
  route_key = "ANY /{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

# Permission for API Gateway to invoke Lambda
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.goatvault_api.execution_arn}/*/*"
}

# Automatic deployment stage
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.goatvault_api.id
  name        = "$default"
  auto_deploy = true
}
