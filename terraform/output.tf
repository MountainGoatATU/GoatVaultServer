output "api_endpoint" {
  value = aws_apigatewayv2_stage.default.invoke_url
}

output "lambda_arn" {
  value = aws_lambda_function.api.arn
}

output "lambda_function_name" {
  description = "Name of the deployed Lambda function"
  value       = aws_lambda_function.this.function_name
}
