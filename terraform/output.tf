output "api_endpoint" {
  value = aws_apigatewayv2_stage.default.invoke_url
}

output "lambda_arn" {
  value = aws_lambda_function.api.arn
}