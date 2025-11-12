package aws

import future.keywords.if
import future.keywords.in

# EC2 Instance Policy: Require encryption for EBS volumes
deny[msg] {
    input.type == "aws:ebs/volume:Volume"
    not input.encrypted
    msg := sprintf("EBS volume '%s' must be encrypted", [input.__name])
}

deny[msg] {
    input.type == "aws:ebs/volume:Volume"
    input.encrypted == false
    msg := sprintf("EBS volume '%s' must be encrypted", [input.__name])
}

# EC2 Instance Policy: No t2.micro in production
deny[msg] {
    input.type == "aws:ec2/instance:Instance"
    input.instanceType == "t2.micro"
    contains(lower(input.__name), "prod")
    msg := sprintf("Production EC2 instance '%s' cannot use t2.micro instance type", [input.__name])
}

# EC2 Instance Policy: Require monitoring
warn[msg] {
    input.type == "aws:ec2/instance:Instance"
    not input.monitoring
    msg := sprintf("EC2 instance '%s' should have detailed monitoring enabled", [input.__name])
}

# Security Group Policy: No unrestricted SSH access
deny[msg] {
    input.type == "aws:ec2/securityGroup:SecurityGroup"
    some rule in input.ingress
    rule.protocol == "tcp"
    rule.fromPort == 22
    some cidr in rule.cidrBlocks
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' allows unrestricted SSH access from 0.0.0.0/0", [input.__name])
}

# Security Group Policy: No unrestricted RDP access
deny[msg] {
    input.type == "aws:ec2/securityGroup:SecurityGroup"
    some rule in input.ingress
    rule.protocol == "tcp"
    rule.fromPort == 3389
    some cidr in rule.cidrBlocks
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' allows unrestricted RDP access from 0.0.0.0/0", [input.__name])
}

# Security Group Policy: Warn on overly permissive rules
warn[msg] {
    input.type == "aws:ec2/securityGroup:SecurityGroup"
    some rule in input.ingress
    rule.protocol == "-1"
    some cidr in rule.cidrBlocks
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' has overly permissive rule allowing all traffic from anywhere", [input.__name])
}
