package main

# __rego__metadoc__ := {
#   "id": "security-group_ingress-ssh-anywhere",
#   "title": "VPC security group rules should not permit ingress from '0.0.0.0/0' to port 3389 (RDP)",
#   "description": "VPC security group rules should not permit ingress from '0.0.0.0/0' to TCP/UDP port 3389 (RDP). VPC security groups should not permit unrestricted access from the internet to port 22 (SSH). Removing unfettered connectivity to remote console services, such as SSH, reduces a server's exposure to risk.",
#   "custom": {
#     "controls": {
#       "CIS": [
#         "CIS_4-2"
#       ]
#     }
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::EC2::SecurityGroup" 
    input.Resources[_].Properties.SecurityGroupIngress[_].FromPort == 3389
    input.Resources[_].Properties.SecurityGroupIngress[_].ToPort == 3389
    input.Resources[_].Properties.SecurityGroupIngress[_].CidrIp == "0.0.0.0/0"
    msg = "Security group rules should not permit ingress from '0.0.0.0/0' to port 3389 (RDP)."
}