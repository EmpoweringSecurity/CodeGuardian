package main

# __rego__metadoc__ := {
#   "id": "auto-scaling-group_elb-health-check",
#   "title": "Auto Scaling groups associated with a load balancer should use load balancer health checks.",
#   "description": "This control checks whether your Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks.",
#   "custom": {
#     "controls": {
#       "AWS Foundational Security Best Practices": [
#         "AutoScaling.1"
#       ]
#     }
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::AutoScaling::AutoScalingGroup" 
    input.Resources[_].Properties.TargetGroupARNs[_] != null
    input.Resources[_].Properties.HealthCheckType != "ELB"
    msg = "Auto Scaling groups associated with a load balancer should use load balancer health checks."
}

deny[msg] {
    input.Resources[_].Type == "AWS::AutoScaling::AutoScalingGroup" 
    input.Resources[_].Properties.LoadBalancerNames[_] != null
    input.Resources[_].Properties.HealthCheckType != "ELB"
    msg = "Auto Scaling groups associated with a load balancer should use load balancer health checks."
}