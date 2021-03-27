package main

# __rego__metadoc__ := {
#   "id": "cloudtrail_cloudwatch-logging",
#   "title": "CloudTrail trails should be integrated with CloudWatch Logs",
#   "description": " For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs.",
#   "custom": {
#     "controls": {
#       "CIS": [
#         "CIS_2-4"
#       ]
#     },
#     "severity": "Medium"
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::CloudTrail::Trail" 
    input.Resources[_].Properties.CloudWatchLogsLogGroupArn == null 
    msg = "CloudTrail trails should be integrated with CloudWatch Logs, check Cloud Watch Logs Group Arn."
}

deny[msg] {
    input.Resources[_].Type == "AWS::CloudTrail::Trail" 
    input.Resources[_].Properties.CloudWatchLogsRoleArn == null 
    msg = "CloudTrail trails should be integrated with CloudWatch Logs, check Cloud Watch Logs Role Arn."
}