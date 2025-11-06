import boto3
import time
from datetime import datetime, timezone, timedelta
import tensorflow as tf
import joblib
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input
import traceback

def get_alb_arn():
    """Get the ALB ARN"""
    elbv2 = boto3.client('elbv2')
    try:
        response = elbv2.describe_load_balancers(Names=['ai-firewall-alb'])
        alb = response['LoadBalancers'][0]
        
        # Wait for ALB to be active
        print("Waiting for ALB to be active...")
        waiter = elbv2.get_waiter('load_balancer_available')
        waiter.wait(LoadBalancerArns=[alb['LoadBalancerArn']])
        print("ALB is active")
        
        return alb['LoadBalancerArn']
    except Exception as e:
        print(f"Error getting ALB ARN: {str(e)}")
        return None

def wait_for_web_acl(wafv2_client, web_acl_id):
    """Wait for Web ACL to be fully ready"""
    print("Waiting for Web ACL to be ready...")
    max_attempts = 6
    for i in range(max_attempts):
        try:
            response = wafv2_client.get_web_acl(
                Name='AI-Firewall-ACL',
                Scope='REGIONAL',
                Id=web_acl_id
            )
            if response['WebACL']:
                print("Web ACL is ready")
                return True
        except Exception as e:
            print(f"Web ACL not ready yet (attempt {i+1}/{max_attempts})")
        time.sleep(10)
    return False

def create_web_acl(wafv2_client):
    """Create WAF Web ACL with rules"""
    try:
        # Delete existing Web ACL if it exists
        try:
            existing_acls = wafv2_client.list_web_acls(Scope='REGIONAL', Limit=100)
            for acl in existing_acls['WebACLs']:
                if acl['Name'] == 'AI-Firewall-ACL':
                    print("Deleting existing Web ACL...")
                    wafv2_client.delete_web_acl(
                        Name='AI-Firewall-ACL',
                        Scope='REGIONAL',
                        Id=acl['Id'],
                        LockToken=acl['LockToken']
                    )
                    print("Waiting 30 seconds for Web ACL deletion to complete...")
                    time.sleep(30)  # Wait for deletion to complete
                    break
        except Exception as e:
            print(f"Error checking/deleting existing Web ACL: {str(e)}")
        
        print("Creating new Web ACL...")
        # Create new Web ACL
        response = wafv2_client.create_web_acl(
            Name='AI-Firewall-ACL',
            Scope='REGIONAL',
            DefaultAction={'Allow': {}},
            Description='WAF rules for AI Firewall',
            Rules=[
                {
                    'Name': 'RateLimit',
                    'Priority': 1,
                    'Statement': {
                        'RateBasedStatement': {
                            'Limit': 100,
                            'AggregateKeyType': 'IP'
                        }
                    },
                    'Action': {'Block': {}},
                    'VisibilityConfig': {
                        'SampledRequestsEnabled': True,
                        'CloudWatchMetricsEnabled': True,
                        'MetricName': 'RateLimitRule'
                    }
                },
                {
                    'Name': 'SuspiciousParameters',
                    'Priority': 2,
                    'Statement': {
                        'OrStatement': {
                            'Statements': [
                                {
                                    'ByteMatchStatement': {
                                        'SearchString': 'debug=1',
                                        'FieldToMatch': {'QueryString': {}},
                                        'TextTransformations': [{'Priority': 1, 'Type': 'NONE'}],
                                        'PositionalConstraint': 'CONTAINS'
                                    }
                                },
                                {
                                    'ByteMatchStatement': {
                                        'SearchString': 'verify=admin',
                                        'FieldToMatch': {'QueryString': {}},
                                        'TextTransformations': [{'Priority': 1, 'Type': 'NONE'}],
                                        'PositionalConstraint': 'CONTAINS'
                                    }
                                }
                            ]
                        }
                    },
                    'Action': {'Block': {}},
                    'VisibilityConfig': {
                        'SampledRequestsEnabled': True,
                        'CloudWatchMetricsEnabled': True,
                        'MetricName': 'SuspiciousParametersRule'
                    }
                }
            ],
            VisibilityConfig={
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'AI-Firewall-Metrics'
            }
        )
        
        web_acl_arn = response['Summary']['ARN']
        web_acl_id = response['Summary']['Id']
        print(f"Created Web ACL: {web_acl_arn}")
        
        # Wait for Web ACL to be fully ready
        if not wait_for_web_acl(wafv2_client, web_acl_id):
            print("Timed out waiting for Web ACL to be ready")
            return None
        
        # Get ALB ARN and ensure it's ready
        alb_arn = get_alb_arn()
        if not alb_arn:
            print("Could not get ALB ARN")
            return None
        
        # Try to associate Web ACL with ALB multiple times
        max_retries = 3
        for i in range(max_retries):
            try:
                print(f"Attempt {i+1}/{max_retries} to associate Web ACL with ALB...")
                wafv2_client.associate_web_acl(
                    WebACLArn=web_acl_arn,
                    ResourceArn=alb_arn
                )
                print("Successfully associated Web ACL with ALB")
                break
            except Exception as e:
                print(f"Attempt {i+1} failed: {str(e)}")
                if i < max_retries - 1:
                    print("Waiting 10 seconds before next attempt...")
                    time.sleep(10)
                else:
                    print("Failed to associate Web ACL with ALB after all retries")
                    return None
        
        return web_acl_arn
    except Exception as e:
        print(f"Error creating Web ACL: {str(e)}")
        return None

def get_web_acl_details(wafv2_client):
    """Get existing Web ACL details"""
    try:
        existing_acls = wafv2_client.list_web_acls(Scope='REGIONAL', Limit=100)
        for acl in existing_acls['WebACLs']:
            if acl['Name'] == 'AI-Firewall-ACL':
                response = wafv2_client.get_web_acl(
                    Name='AI-Firewall-ACL',
                    Scope='REGIONAL',
                    Id=acl['Id']
                )
                return response['WebACL']
        return None
    except Exception as e:
        print(f"Error getting Web ACL details: {str(e)}")
        return None

def get_cloudwatch_metrics():
    """Get CloudWatch metrics for WAF and network traffic"""
    cloudwatch = boto3.client('cloudwatch')
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=15)  # Increased window further
    
    # Get metrics for each rule
    wafv2_client = boto3.client('wafv2', region_name='us-east-1')
    web_acl = get_web_acl_details(wafv2_client)
    if not web_acl:
        return 0, 0
        
    blocked_requests = get_blocked_requests()
    total_requests = get_total_requests()
    
    return blocked_requests, total_requests

def get_guardduty_findings():
    """Get recent GuardDuty findings."""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=5)
        
        guardduty = boto3.client('guardduty')
        detectors = guardduty.list_detectors()
        if not detectors['DetectorIds']:
            print("No GuardDuty detector found")
            return []
            
        detector_id = detectors['DetectorIds'][0]
        response = guardduty.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                'Criterion': {
                    'updatedAt': {
                        'Gte': int(start_time.timestamp())
                    }
                }
            }
        )
        return response.get('FindingIds', [])
    except Exception as e:
        print(f"Error getting GuardDuty findings: {str(e)}")
        return []

def create_waf_rule(wafv2_client, web_acl_name, rule_name, rule_type='rate_limit', limit=100):
    try:
        if rule_type == 'rate_limit':
            return {
                'Name': rule_name,
                'Priority': 1,
                'Statement': {
                    'RateBasedStatement': {
                        'Limit': limit,
                        'AggregateKeyType': 'IP'
                    }
                },
                'Action': {'Block': {}},
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': f"{rule_name}Metric"
                }
            }
        elif rule_type == 'suspicious_params':
            return {
                'Name': rule_name,
                'Priority': 2,
                'Statement': {
                    'OrStatement': {
                        'Statements': [
                            {
                                'ByteMatchStatement': {
                                    'SearchString': 'test=true',
                                    'FieldToMatch': {'QueryString': {}},
                                    'TextTransformations': [{'Priority': 1, 'Type': 'NONE'}],
                                    'PositionalConstraint': 'CONTAINS'
                                }
                            },
                            {
                                'ByteMatchStatement': {
                                    'SearchString': 'debug=1',
                                    'FieldToMatch': {'QueryString': {}},
                                    'TextTransformations': [{'Priority': 1, 'Type': 'NONE'}],
                                    'PositionalConstraint': 'CONTAINS'
                                }
                            }
                        ]
                    }
                },
                'Action': {'Block': {}},
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': f"{rule_name}Metric"
                }
            }
    except Exception as e:
        print(f"Error creating WAF rule: {str(e)}")
        return None

def get_traffic_features(metrics):
    """Extract relevant features from traffic metrics for NIDS model"""
    # Calculate derived features
    block_rate = metrics.get('BlockedRequests', 0) / max(metrics.get('RequestCount', 1), 1)
    unique_ip_ratio = metrics.get('UniqueIPs', 0) / max(metrics.get('RequestCount', 1), 1)
    syn_flood_rate = metrics.get('SynFloodCount', 0) / 60  # per minute
    
    # Create feature array in the correct order
    features = [
        block_rate,                                    # Ratio of blocked requests
        unique_ip_ratio,                              # Ratio of unique IPs to total requests
        metrics.get('RequestRate', 0),                # Requests per second
        syn_flood_rate,                               # SYN flood rate
        metrics.get('GuardDutyFindings', 0),          # Number of GuardDuty findings
        metrics.get('ResponseCode403', 0),            # Number of 403 responses
        metrics.get('ResponseCode404', 0),            # Number of 404 responses
    ]
    
    # Convert to numpy array for scaling
    return np.array(features).reshape(1, -1)

def analyze_traffic_patterns(metrics):
    """Analyze traffic patterns to identify potential attack signatures"""
    patterns = []
    
    # Calculate key indicators
    block_rate = metrics.get('BlockedRequests', 0) / max(metrics.get('RequestCount', 1), 1)
    requests_per_ip = metrics.get('RequestCount', 0) / max(metrics.get('UniqueIPs', 1), 1)
    
    # Pattern 1: API abuse detection
    if metrics.get('APIAbuseAttempts', 0) > 1:
        patterns.append({
            "name": "APIAbuseProtection",
            "match_string": "page=1&size=1000|q=*|format=csv",
            "priority": 1
        })
    
    # Pattern 2: Path traversal detection
    if metrics.get('PathTraversalAttempts', 0) > 1:
        patterns.append({
            "name": "PathTraversalProtection",
            "match_string": "\\.\\./|\\.\\.\\/|%2e%2e%2f|\\.\\.%2f",
            "priority": 2
        })
    
    # Pattern 3: SQL injection detection
    if metrics.get('SQLInjectionAttempts', 0) > 1:
        patterns.append({
            "name": "SQLInjectionProtection",
            "match_string": "UNION SELECT|OR 1=1|--",
            "priority": 3
        })
    
    # Pattern 4: NoSQL injection detection
    if metrics.get('NoSQLInjectionAttempts', 0) > 1:
        patterns.append({
            "name": "NoSQLInjectionProtection",
            "match_string": "\\$ne|\\$exists|\\$where",
            "priority": 4
        })
    
    return patterns

def create_pattern_rule(wafv2_client, web_acl_name, pattern):
    """Create a new WAF rule based on detected pattern"""
    if pattern.get('type') == 'rate_based':
        return {
            'Name': pattern['name'],
            'Priority': pattern['priority'],
            'Statement': {
                'RateBasedStatement': {
                    'Limit': pattern['limit'],
                    'AggregateKeyType': 'IP'
                }
            },
            'Action': {'Block': {}},
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': f"{pattern['name']}Metric"
            }
        }
    else:
        # Create regex pattern match rule
        return {
            'Name': pattern['name'],
            'Priority': pattern['priority'],
            'Statement': {
                'RegexPatternSetReferenceStatement': {
                    'RegexPatternSetId': pattern['match_string'],
                    'FieldToMatch': {
                        'UriPath': {}
                    },
                    'TextTransformations': [
                        {
                            'Priority': 1,
                            'Type': 'URL_DECODE'
                        },
                        {
                            'Priority': 2,
                            'Type': 'HTML_ENTITY_DECODE'
                        }
                    ]
                }
            },
            'Action': {'Block': {}},
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': f"{pattern['name']}Metric"
            }
        }

def analyze_and_update_rules(wafv2_client, web_acl_name, metrics, guardduty_findings):
    """Analyze current metrics and update WAF rules if needed."""
    try:
        # Get current metrics
        features = get_current_metrics()
        print(f"Raw features shape: {features.shape}")
        print(f"Raw features: {features}")
        
        # Load and create model if needed
        model = create_nids_model()
        
        # Make prediction
        prediction = model.predict(features, verbose=0)
        print(f"Attack probability: {prediction[0][0]:.2f}")
        
        # Update rules based on prediction and additional metrics
        attack_indicators = 0
        
        # Check prediction probability
        if prediction[0][0] > 0.3:
            attack_indicators += 1
            
        # Check API abuse
        if metrics.get('APIAbuseAttempts', 0) > 1:
            attack_indicators += 1
            
        # Check path traversal
        if metrics.get('PathTraversalAttempts', 0) > 1:
            attack_indicators += 1
            
        # Check SQL injection
        if metrics.get('SQLInjectionAttempts', 0) > 1:
            attack_indicators += 1
            
        # Check NoSQL injection
        if metrics.get('NoSQLInjectionAttempts', 0) > 1:
            attack_indicators += 1
            
        print(f"\nAttack Indicators Analysis:")
        print(f"- NIDS Prediction: {prediction[0][0]:.2f} (threshold: 0.3)")
        print(f"- API Abuse Attempts: {metrics.get('APIAbuseAttempts', 0)} (threshold: 1)")
        print(f"- Path Traversal Attempts: {metrics.get('PathTraversalAttempts', 0)} (threshold: 1)")
        print(f"- SQL Injection Attempts: {metrics.get('SQLInjectionAttempts', 0)} (threshold: 1)")
        print(f"- NoSQL Injection Attempts: {metrics.get('NoSQLInjectionAttempts', 0)} (threshold: 1)")
        print(f"Total Indicators: {attack_indicators}/5")
        
        # Update rules if we have enough indicators
        if attack_indicators >= 2:
            print("\nPotential attack detected based on multiple indicators")
            print("Analyzing traffic patterns and updating WAF rules...")
            
            # Get attack patterns
            patterns = analyze_traffic_patterns(metrics)
            
            # Update WAF rules based on patterns
            if patterns:
                update_waf_rules(True, patterns)
        else:
            print("\nNo immediate threat detected")
            print("Maintaining normal protection levels...")
            update_waf_rules(False)
            
    except Exception as e:
        print(f"Error in NIDS analysis: {str(e)}")
        traceback.print_exc()

def get_victim_alb():
    """Get the Application Load Balancer associated with the victim instance"""
    try:
        # Get the victim instance ID
        ec2 = boto3.client('ec2')
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'tag:Name', 'Values': ['Victim-Server']},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )
        
        instance_id = None
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                break
        
        if not instance_id:
            print("Could not find victim instance")
            return None
            
        # Get the ALB associated with the instance
        elbv2 = boto3.client('elbv2')
        response = elbv2.describe_load_balancers()
        
        for lb in response['LoadBalancers']:
            # Check if this ALB has our instance
            target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
            for tg in target_groups['TargetGroups']:
                targets = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                for target in targets['TargetHealthDescriptions']:
                    if target['Target']['Id'] == instance_id:
                        return lb['LoadBalancerArn']
        
        print("No ALB found for victim instance")
        return None
    except Exception as e:
        print(f"Error getting ALB: {str(e)}")
        return None

def associate_web_acl(wafv2_client, web_acl_arn):
    """Associate Web ACL with the victim's ALB"""
    try:
        alb_arn = get_victim_alb()
        if not alb_arn:
            print("Could not find ALB to associate with Web ACL")
            return False
            
        wafv2_client.associate_web_acl(
            WebACLArn=web_acl_arn,
            ResourceArn=alb_arn
        )
        print(f"Associated Web ACL with ALB: {alb_arn}")
        return True
    except Exception as e:
        print(f"Error associating Web ACL: {str(e)}")
        return False

def get_active_rules():
    """Get list of active WAF rules."""
    try:
        wafv2_client = boto3.client('wafv2', region_name='us-east-1')
        web_acl = get_web_acl_details(wafv2_client)
        if not web_acl:
            return []
        return web_acl.get('Rules', [])
    except Exception as e:
        print(f"Error getting active rules: {str(e)}")
        return []

def create_nids_model():
    """Create and return a new NIDS model."""
    model = Sequential([
        Input(shape=(7,)),  # Input layer with shape specification
        Dense(14, activation='relu'),
        Dense(10, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def get_current_metrics():
    """Get current metrics for NIDS analysis."""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=5)
        
        # Get metrics from CloudWatch
        cloudwatch = boto3.client('cloudwatch')
        response = cloudwatch.get_metric_statistics(
            Namespace='AIFirewall/Metrics',
            MetricName='RequestRate',
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=['Average']
        )
        request_rate = response['Datapoints'][0]['Average'] if response['Datapoints'] else 0
        
        response = cloudwatch.get_metric_statistics(
            Namespace='AIFirewall/Metrics',
            MetricName='UniqueIPs',
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=['Maximum']
        )
        unique_ips = response['Datapoints'][0]['Maximum'] if response['Datapoints'] else 0
        
        # Get WAF metrics
        blocked_requests = get_blocked_requests()
        total_requests = get_total_requests()
        
        # Create feature vector
        features = [
            request_rate,              # Request rate
            unique_ips,               # Number of unique IPs
            blocked_requests,         # Number of blocked requests
            total_requests,           # Total requests
            blocked_requests / max(total_requests, 1),  # Block ratio
            len(get_active_rules()),  # Number of active rules
            len(get_guardduty_findings())  # Number of GuardDuty findings
        ]
        
        return np.array(features).reshape(1, 7)
    except Exception as e:
        print(f"Error getting metrics: {str(e)}")
        return np.zeros((1, 7))

def get_blocked_requests():
    """Get the number of requests blocked by WAF rules."""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=5)
        
        cloudwatch = boto3.client('cloudwatch')
        wafv2_client = boto3.client('wafv2', region_name='us-east-1')
        web_acl = get_web_acl_details(wafv2_client)
        if not web_acl:
            return 0
            
        web_acl_id = web_acl['Id']
        total_blocked = 0
        
        # Get metrics for each rule
        for rule in web_acl['Rules']:
            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/WAFV2',
                MetricName='BlockedRequests',
                Dimensions=[
                    {'Name': 'WebACL', 'Value': web_acl['Name']},
                    {'Name': 'Rule', 'Value': rule['Name']},
                    {'Name': 'Region', 'Value': 'us-east-1'}
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=['Sum']
            )
            if response['Datapoints']:
                total_blocked += response['Datapoints'][0]['Sum']
        
        return int(total_blocked)
    except Exception as e:
        print(f"Error getting blocked requests: {str(e)}")
        return 0

def get_total_requests():
    """Get the total number of requests processed by WAF."""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=5)
        
        cloudwatch = boto3.client('cloudwatch')
        wafv2_client = boto3.client('wafv2', region_name='us-east-1')
        web_acl = get_web_acl_details(wafv2_client)
        if not web_acl:
            return 0
            
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/WAFV2',
            MetricName='AllowedRequests',
            Dimensions=[
                {'Name': 'WebACL', 'Value': web_acl['Name']},
                {'Name': 'Region', 'Value': 'us-east-1'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=['Sum']
        )
        
        allowed = response['Datapoints'][0]['Sum'] if response['Datapoints'] else 0
        blocked = get_blocked_requests()
        
        return int(allowed + blocked)
    except Exception as e:
        print(f"Error getting total requests: {str(e)}")
        return 0

def update_waf_rules(is_attack_detected, patterns=None):
    """Update WAF rules based on attack detection and patterns."""
    try:
        wafv2_client = boto3.client('wafv2', region_name='us-east-1')
        web_acl = get_web_acl_details(wafv2_client)
        if not web_acl:
            print("Failed to get Web ACL details")
            return
            
        current_rules = web_acl.get('Rules', [])
        rules_updated = False
        
        # Update rate limit rule
        for rule in current_rules:
            if rule['Name'] == 'RateLimit':
                current_limit = rule['Statement']['RateBasedStatement']['Limit']
                if is_attack_detected:
                    new_limit = max(current_limit // 2, 25)
                else:
                    new_limit = min(current_limit * 2, 100)
                    
                if new_limit != current_limit:
                    rule['Statement']['RateBasedStatement']['Limit'] = new_limit
                    rules_updated = True
                    print(f"Updated rate limit to {new_limit} requests per 5 minutes")
        
        # Add new pattern-based rules if detected
        if patterns:
            for pattern in patterns:
                new_rule = create_pattern_rule(wafv2_client, web_acl['Name'], pattern)
                if new_rule:
                    # Check if rule already exists
                    exists = False
                    for existing_rule in current_rules:
                        if existing_rule['Name'] == new_rule['Name']:
                            exists = True
                            break
                    
                    if not exists:
                        current_rules.append(new_rule)
                        rules_updated = True
                        print(f"Added new rule: {new_rule['Name']}")
        
        if rules_updated:
            try:
                # Get current version of Web ACL
                response = wafv2_client.get_web_acl(
                    Name=web_acl['Name'],
                    Scope='REGIONAL',
                    Id=web_acl['Id']
                )
                
                # Update Web ACL with new rules
                response = wafv2_client.update_web_acl(
                    Name=web_acl['Name'],
                    Scope='REGIONAL',
                    Id=web_acl['Id'],
                    DefaultAction=web_acl['DefaultAction'],
                    Rules=current_rules,
                    LockToken=response['LockToken'],
                    Description='Web ACL updated with new attack patterns',
                    VisibilityConfig=web_acl['VisibilityConfig']
                )
                print("WAF rules updated successfully")
            except Exception as e:
                print(f"Error updating WAF ACL: {str(e)}")
                traceback.print_exc()
        else:
            print("No rule updates needed")
            
    except Exception as e:
        print(f"Error updating WAF rules: {str(e)}")
        traceback.print_exc()

def main():
    try:
        print("Starting monitoring...")
        
        # Get Web ACL details
        wafv2_client = boto3.client('wafv2', region_name='us-east-1')
        web_acl = get_web_acl_details(wafv2_client)
        if not web_acl:
            print("Web ACL not found")
            return
            
        print(f"\nWeb ACL Details:")
        print(f"Name: {web_acl['Name']}")
        print(f"ID: {web_acl['Id']}")
        print(f"ARN: {web_acl['ARN']}")
        print(f"Rules: {[rule['Name'] for rule in web_acl['Rules']]}")
        
        # Get metrics and findings
        blocked_requests, total_requests = get_cloudwatch_metrics()
        guardduty_findings = get_guardduty_findings()
        
        # Get additional metrics from CloudWatch
        cloudwatch = boto3.client('cloudwatch')
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=5)
        
        # Get NIDS metrics
        try:
            response = cloudwatch.get_metric_statistics(
                Namespace='AIFirewall/NIDS',
                MetricName='RequestRate',
                Dimensions=[],
                StartTime=start_time,
                EndTime=end_time,
                Period=60,
                Statistics=['Average']
            )
            request_rate = max([point['Average'] for point in response['Datapoints']]) if response['Datapoints'] else 0
            
            response = cloudwatch.get_metric_statistics(
                Namespace='AIFirewall/NIDS',
                MetricName='UniqueIPs',
                Dimensions=[],
                StartTime=start_time,
                EndTime=end_time,
                Period=60,
                Statistics=['Maximum']
            )
            unique_ips = max([point['Maximum'] for point in response['Datapoints']]) if response['Datapoints'] else 0
            
            print("\nNIDS Metrics from CloudWatch:")
            print(f"Request Rate: {request_rate:.2f} requests/second")
            print(f"Unique IPs: {unique_ips}")
            
        except Exception as e:
            print(f"Error getting NIDS metrics: {str(e)}")
            request_rate = 0
            unique_ips = 0
        
        # Collect all metrics for analysis
        metrics = {
            'RequestCount': total_requests,
            'BlockedRequests': blocked_requests,
            'AllowedRequests': total_requests - blocked_requests,
            'GuardDutyFindings': guardduty_findings,
            'RequestRate': request_rate,
            'UniqueIPs': unique_ips,
            'ResponseCode403': blocked_requests,  # Assuming blocked requests result in 403
            'ResponseCode404': total_requests - blocked_requests,  # Assuming remaining requests are 404s
            'APIAbuseAttempts': 0,
            'PathTraversalAttempts': 0,
            'SQLInjectionAttempts': 0,
            'NoSQLInjectionAttempts': 0
        }
        
        # Analyze traffic and update rules
        analyze_and_update_rules(wafv2_client, web_acl['Name'], metrics, guardduty_findings)
        
        # Print current status
        print("\nCurrent Status:")
        print(f"WAF Blocked Requests: {blocked_requests}")
        print(f"Total Requests: {total_requests}")
        print(f"GuardDuty Findings: {guardduty_findings}")
        print(f"Active WAF Rules: {len(web_acl['Rules'])}")
        print(f"Request Rate: {metrics['RequestRate']:.2f} requests/second")
        print(f"Unique IPs: {metrics['UniqueIPs']}")
        
        print("\nMonitoring completed")
        
    except Exception as e:
        print(f"Error during monitoring: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

if __name__ == '__main__':
    main() 