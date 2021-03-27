# CodeGuardian
## AWS RULES 
## AWS CIS Benchmark v1.2.0
1 Identity and Access Management | |
--- | --- |
Rule | CloudFormation | 
1.1 Avoid the use of the "root" account (Scored) | Not applicable |
1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored) | Not applicable |
1.3 Ensure credentials unused for 90 days or greater are disabled (Scored) | Not applicable |
1.4 Ensure access keys are rotated every 90 days or less (Scored) | Not applicable |
1.5 Ensure IAM password policy requires at least one uppercase letter (Scored) | Not applicable |
1.6 Ensure IAM password policy require at least one lowercase letter (Scored) | Not applicable |
1.7 Ensure IAM password policy require at least one symbol (Scored) | Not applicable |
1.8 Ensure IAM password policy require at least one number (Scored) | Not applicable |
1.9 Ensure IAM password policy requires minimum length of 14 or greater (Scored) | Not applicable |
1.10 Ensure IAM password policy prevents password reuse (Scored) | Not applicable |
1.11 Ensure IAM password policy expires passwords within 90 days or less (Scored) | Not applicable |
1.12 Ensure no root account access key exists (Scored) | Not applicable |
1.13 Ensure MFA is enabled for the "root" account (Scored) | Not applicable |
1.14 Ensure hardware MFA is enabled for the "root" account (Scored) | Not applicable |
1.15 Ensure security questions are registered in the AWS account (Not Scored) | Not applicable |
1.16 Ensure IAM policies are attached only to groups or roles (Scored) | Complete | 
1.17 Maintain current contact details (Not Scored) | Not applicable |
1.18 Ensure security contact information is registered (Not Scored) | Not applicable |
1.19 Ensure IAM instance roles are used for AWS resource access from instances (Not Scored) |
1.20 Ensure a support role has been created to manage incidents with AWS Support (Scored) | Not applicable |
1.21 Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored) | Not applicable |
1.22 Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored) | Complete | 

2 Logging | |
--- | --- |
Rule | CloudFormation | 
2.1 Ensure CloudTrail is enabled in all regions (Scored) | Complete | 
2.2 Ensure CloudTrail log file validation is enabled (Scored) | Complete | 
2.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible (Scored) | Possible | 
2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored) | Partial | 
2.5 Ensure AWS Config is enabled in all regions (Scored) | Not applicable | 
2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored) | Possible | 
2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored) | Partial | 
2.8 Ensure rotation for customer created CMKs is enabled (Scored) | Partial | 
2.9 Ensure VPC flow logging is enabled in all VPCs (Scored) | Not applicable | 

3 Monitoring | |
--- | --- |
Rule | CloudFormation | 
3.1 Ensure a log metric filter and alarm exist for unauthorized API calls (Scored) | Not applicable |
3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored) | Not applicable |
3.3 Ensure a log metric filter and alarm exist for usage of "root" account (Scored) | Not applicable |
3.4 Ensure a log metric filter and alarm exist for IAM policy changes (Scored) | Not applicable |
3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored) | Not applicable |
3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored) | Not applicable |
3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored) | Not applicable |
3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored) | Not applicable |
3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored) | Not applicable |
3.10 Ensure a log metric filter and alarm exist for security group changes (Scored) | Not applicable |
3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored) | Not applicable |
3.12 Ensure a log metric filter and alarm exist for changes to network gateways (Scored) | Not applicable |
3.13 Ensure a log metric filter and alarm exist for route table changes (Scored) | Not applicable |
3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored) | Not applicable |

4 Networking | |
--- | --- |
Rule | CloudFormation | 
4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored) | Partial | 
4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored) | Partial | 
4.3 Ensure the default security group of every VPC restricts all traffic (Scored) | Not applicable | 
4.4 Ensure routing tables for VPC peering are "least access" (Not Scored) | Not applicable | 

## AWS Foundational Security Best Practices standard
Rule | CloudFormation | 
ACM.1 Imported ACM certificates should be renewed after a specified time period | Not applicable |
APIGateway.1 API Gateway REST and HTTP API logging should be enabled | Partial |
AutoScaling.1 Auto Scaling groups associated with a load balancer should use load balancer health checks | Partial | 
CloudFront.1 CloudFront distributions should have a default root object configured | Partial |
CloudFront.2 CloudFront distributions should have origin access identity enabled | Partial |
CloudFront.3 CloudFront distributions should require encryption in transit | Complete |
CloudFront.4 CloudFront distributions should have origin failover configured | Partial |