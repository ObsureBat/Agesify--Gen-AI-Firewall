import boto3
import time

def get_victim_instance():
    """Get the victim instance details"""
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(
        Filters=[
            {'Name': 'tag:Name', 'Values': ['Victim-Server']},
            {'Name': 'instance-state-name', 'Values': ['running']}
        ]
    )
    
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            return {
                'id': instance['InstanceId'],
                'vpc': instance['VpcId'],
                'az': instance['Placement']['AvailabilityZone']
            }
    return None

def get_subnets(vpc_id):
    """Get two subnets in different AZs"""
    ec2 = boto3.client('ec2')
    response = ec2.describe_subnets(
        Filters=[
            {'Name': 'vpc-id', 'Values': [vpc_id]},
            {'Name': 'state', 'Values': ['available']}
        ]
    )
    
    # Group subnets by AZ
    subnets_by_az = {}
    for subnet in response['Subnets']:
        az = subnet['AvailabilityZone']
        if az not in subnets_by_az:
            subnets_by_az[az] = []
        subnets_by_az[az].append(subnet['SubnetId'])
    
    # Get subnets from different AZs
    selected_subnets = []
    for az in subnets_by_az:
        if len(selected_subnets) < 2:
            selected_subnets.append(subnets_by_az[az][0])
    
    return selected_subnets if len(selected_subnets) >= 2 else None

def get_security_group():
    """Get or create security group for ALB"""
    ec2 = boto3.client('ec2')
    vpc_id = None
    
    # Get VPC ID from victim instance
    instance = get_victim_instance()
    if instance:
        vpc_id = instance['vpc']
    
    if not vpc_id:
        print("Could not find VPC")
        return None
    
    # Check if security group exists
    response = ec2.describe_security_groups(
        Filters=[
            {'Name': 'group-name', 'Values': ['ai-firewall-alb-sg']},
            {'Name': 'vpc-id', 'Values': [vpc_id]}
        ]
    )
    
    if response['SecurityGroups']:
        return response['SecurityGroups'][0]['GroupId']
    
    # Create new security group
    response = ec2.create_security_group(
        GroupName='ai-firewall-alb-sg',
        Description='Security group for AI Firewall ALB',
        VpcId=vpc_id
    )
    
    group_id = response['GroupId']
    
    # Add inbound rules
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    
    return group_id

def create_alb():
    """Create Application Load Balancer"""
    instance = get_victim_instance()
    if not instance:
        print("Could not find victim instance")
        return
    
    # Get subnets from different AZs
    subnets = get_subnets(instance['vpc'])
    if not subnets:
        print("Could not find two subnets in different AZs")
        return
    
    security_group = get_security_group()
    if not security_group:
        print("Could not create security group")
        return
    
    elbv2 = boto3.client('elbv2')
    
    try:
        # Check if ALB already exists
        existing_albs = elbv2.describe_load_balancers(Names=['ai-firewall-alb'])
        print("ALB already exists, using existing one")
        alb_arn = existing_albs['LoadBalancers'][0]['LoadBalancerArn']
    except elbv2.exceptions.LoadBalancerNotFoundException:
        # Create ALB
        print("Creating new ALB...")
        response = elbv2.create_load_balancer(
            Name='ai-firewall-alb',
            Subnets=subnets,
            SecurityGroups=[security_group],
            Scheme='internet-facing',
            Type='application',
            IpAddressType='ipv4'
        )
        alb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
        print(f"Created ALB: {alb_arn}")
    
    try:
        # Check if target group exists
        existing_tgs = elbv2.describe_target_groups(Names=['ai-firewall-tg'])
        target_group_arn = existing_tgs['TargetGroups'][0]['TargetGroupArn']
        print("Target group already exists")
    except elbv2.exceptions.TargetGroupNotFoundException:
        # Create target group
        print("Creating new target group...")
        response = elbv2.create_target_group(
            Name='ai-firewall-tg',
            Protocol='HTTP',
            Port=80,
            VpcId=instance['vpc'],
            HealthCheckProtocol='HTTP',
            HealthCheckPath='/',
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=2,
            UnhealthyThresholdCount=2,
            TargetType='instance'
        )
        target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
        print(f"Created target group: {target_group_arn}")
    
    # Register instance with target group
    elbv2.register_targets(
        TargetGroupArn=target_group_arn,
        Targets=[{'Id': instance['id']}]
    )
    print(f"Registered instance {instance['id']} with target group")
    
    # Check if listener exists
    listeners = elbv2.describe_listeners(LoadBalancerArn=alb_arn)
    if not listeners['Listeners']:
        # Create listener
        print("Creating listener...")
        elbv2.create_listener(
            LoadBalancerArn=alb_arn,
            Protocol='HTTP',
            Port=80,
            DefaultActions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': target_group_arn
                }
            ]
        )
        print("Created listener")
    else:
        print("Listener already exists")
    
    # Wait for ALB to be active
    print("Waiting for ALB to be active...")
    waiter = elbv2.get_waiter('load_balancer_available')
    waiter.wait(LoadBalancerArns=[alb_arn])
    
    # Get ALB DNS name
    response = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])
    dns_name = response['LoadBalancers'][0]['DNSName']
    print(f"\nALB is ready! DNS name: {dns_name}")
    return dns_name

def main():
    try:
        print("Setting up Application Load Balancer...")
        dns_name = create_alb()
        if dns_name:
            print("\nNext steps:")
            print("1. Update your attack simulation to use this DNS name")
            print("2. Associate the WAF Web ACL with this ALB")
            print("3. Run the attack simulation again")
    except Exception as e:
        print(f"Error setting up ALB: {str(e)}")

if __name__ == '__main__':
    main() 