import boto3
import json
import time
from botocore.exceptions import ClientError

def create_vpc():
    """Create VPC and necessary networking components"""
    ec2 = boto3.client('ec2')
    
    # Create VPC
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    vpc_id = vpc['Vpc']['VpcId']
    
    # Create subnets
    subnet1 = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock='10.0.1.0/24',
        AvailabilityZone='us-east-1a'
    )
    
    subnet2 = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock='10.0.2.0/24',
        AvailabilityZone='us-east-1b'
    )
    
    return vpc_id, subnet1['Subnet']['SubnetId'], subnet2['Subnet']['SubnetId']

def create_security_group(vpc_id):
    """Create security group for EC2 instances"""
    ec2 = boto3.client('ec2')
    
    security_group = ec2.create_security_group(
        GroupName='AI-Firewall-SG',
        Description='Security group for AI Firewall project',
        VpcId=vpc_id
    )
    
    # Add inbound rules
    ec2.authorize_security_group_ingress(
        GroupId=security_group['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    
    return security_group['GroupId']

def create_ec2_instances(subnet_ids, security_group_id):
    """Create attacker and victim EC2 instances"""
    ec2 = boto3.client('ec2')
    
    # Use Amazon Linux 2 AMI
    response = ec2.describe_images(
        Filters=[
            {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
            {'Name': 'state', 'Values': ['available']}
        ],
        Owners=['amazon']
    )
    ami_id = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
    
    # Create instances
    instances = ec2.run_instances(
        ImageId=ami_id,
        InstanceType='t2.micro',
        MaxCount=2,
        MinCount=2,
        SecurityGroupIds=[security_group_id],
        SubnetId=subnet_ids[0],
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': 'Attacker'},
                    {'Key': 'Name', 'Value': 'Victim'}
                ]
            }
        ]
    )
    
    return [instance['InstanceId'] for instance in instances['Instances']]

def setup_flow_logs(vpc_id):
    """Set up VPC Flow Logs"""
    logs = boto3.client('logs')
    ec2 = boto3.client('ec2')
    
    # Create log group
    log_group_name = f'/aws/vpc/flowlogs/{vpc_id}'
    try:
        logs.create_log_group(logGroupName=log_group_name)
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
            raise
    
    # Create IAM role for flow logs
    iam = boto3.client('iam')
    role_name = 'VPCFlowLogsRole'
    
    try:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'vpc-flow-logs.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            })
        )
        
        # Attach necessary policies
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName='VPCFlowLogsPolicy',
            PolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': [
                        'logs:CreateLogGroup',
                        'logs:CreateLogStream',
                        'logs:PutLogEvents',
                        'logs:DescribeLogGroups',
                        'logs:DescribeLogStreams'
                    ],
                    'Resource': '*'
                }]
            })
        )
        
    except ClientError as e:
        if e.response['Error']['Code'] != 'EntityAlreadyExists':
            raise
    
    # Enable flow logs
    ec2.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType='VPC',
        TrafficType='ALL',
        LogGroupName=log_group_name,
        DeliverLogsPermissionArn=role['Role']['Arn']
    )

def main():
    """Main deployment function"""
    try:
        print("Starting deployment...")
        
        # Create VPC and networking
        vpc_id, subnet1_id, subnet2_id = create_vpc()
        print(f"Created VPC: {vpc_id}")
        
        # Create security group
        sg_id = create_security_group(vpc_id)
        print(f"Created security group: {sg_id}")
        
        # Create EC2 instances
        instance_ids = create_ec2_instances([subnet1_id, subnet2_id], sg_id)
        print(f"Created EC2 instances: {instance_ids}")
        
        # Setup flow logs
        setup_flow_logs(vpc_id)
        print("Set up VPC Flow Logs")
        
        print("\nDeployment completed successfully!")
        print("\nNext steps:")
        print("1. Configure your AWS credentials")
        print("2. Update the Lambda function with your SageMaker endpoint")
        print("3. Set up CloudWatch dashboards for monitoring")
        
    except Exception as e:
        print(f"Error during deployment: {str(e)}")
        raise

if __name__ == '__main__':
    main() 