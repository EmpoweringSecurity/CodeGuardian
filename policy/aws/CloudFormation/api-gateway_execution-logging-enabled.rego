package main

# __rego__metadoc__ := {
#   "id": "api-gateway_execution-logging-enabled",
#   "title": "API Gateway REST or HTTP API stages should have execution logging enabled.",
#   "description": "This control checks whether all methods of an Amazon API Gateway REST or HTTP API stage have logging enabled. The control fails if logging is not enabled for all methods of a stage or if loggingLevel is neither ERROR nor INFO.",
#   "custom": {
#     "controls": {
#       "AWS Foundational Security Best Practices": [
#         "APIGateway.1"
#       ]
#     }
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::ApiGateway::Stage" 
    input.Resources[_].Properties.AccessLogSetting == null
    msg = "API Gateway REST or HTTP API stages should have execution logging enabled."
}

deny[msg] {
    input.Resources[_].Type == "AWS::ApiGateway::Stage" 
    input.Resources[_].Properties.AccessLogSetting.DestinationArn == null
    input.Resources[_].Properties.AccessLogSetting.Format == null
    msg = "API Gateway REST or HTTP API stages should have execution logging enabled."
}

deny[msg] {
    input.Resources[_].Type == "AWS::ApiGatewayV2::Stage" 
    input.Resources[_].Properties.AccessLogSetting == null
    msg = "API Gateway REST or HTTP API stages should have execution logging enabled."
}

deny[msg] {
    input.Resources[_].Type == "AWS::ApiGatewayV2::Stage" 
    input.Resources[_].Properties.AccessLogSetting.DestinationArn == null
    input.Resources[_].Properties.AccessLogSetting.Format == null
    msg = "API Gateway REST or HTTP API stages should have execution logging enabled."
}