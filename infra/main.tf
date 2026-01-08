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

# ============================
# LAMBDAS
# ============================

# One Lambda
resource "aws_lambda_function" "api" {
  function_name = var.aws_lambda_function_name
  role          = aws_iam_role.lambda_exec_role.arn
  runtime       = "python3.11"
  handler       = "app.lambda_handler.handler"

  timeout     = 30
  memory_size = 512

  filename         = "${path.module}/deployment/deployment.zip"
  source_code_hash = filebase64sha256("${path.module}/deployment/deployment.zip")

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
