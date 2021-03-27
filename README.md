# CodeGuardian
To help you enforce policy based control to guard your cloud from vulnerable code and improve the quality. This project
is a library of rules that helps you achieve that outcome. 

## Project Status
This is currently in early development phase. We are continuing to build out the rule library.

## Terminology
A **control** represents an individual recommendation within a compliance standard
A **rule** is a Rego policy that validates whether a cloud resource violates a control (or multiple controls)

## Improvements
- #TODO - Improve naming spaces, from main to aws, azure, gcp.
- #TODO - Add in cloudtrail_cloudwatch-logging, if CloudWatch property is missing, remove.
- #TODO - Check for ssh in port ranges, not just 22:22 to and from
- #TODO - Finish the remain rules for AWS Foundational Security Best Practices standard
- #TODO - Implement strong unit testing