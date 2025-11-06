import json
import boto3
import os
import time
from datetime import datetime

def process_flow_logs(event, context):
    """Process VPC Flow Logs and detect threats"""
    try:
        # Initialize AWS clients
        sagemaker = boto3.client('sagemaker-runtime')
        wafv2 = boto3.client('wafv2')
        cloudwatch = boto3.client('cloudwatch')
        
        # Get the flow log data
        log_data = event['awslogs']['data']
        
        # Process each flow log entry
        for flow_record in log_data:
            # Extract features from flow log
            features = extract_features(flow_record)
            
            # Get prediction from SageMaker endpoint
            response = sagemaker.invoke_endpoint(
                EndpointName='ai-firewall-endpoint',
                ContentType='application/json',
                Body=json.dumps(features)
            )
            
            prediction = json.loads(response['Body'].read())
            threat_score = prediction['threat_probability']
            
            # If threat detected, update WAF rules
            if threat_score > 0.8:  # High threat threshold
                source_ip = flow_record.get('srcaddr')
                if source_ip:
                    update_waf_rules(wafv2, source_ip)
                    
                # Log the threat detection
                cloudwatch.put_metric_data(
                    Namespace='AI-Firewall',
                    MetricData=[{
                        'MetricName': 'ThreatDetections',
                        'Value': 1,
                        'Unit': 'Count',
                        'Timestamp': datetime.now()
                    }]
                )
        
        return {
            'statusCode': 200,
            'body': json.dumps('Successfully processed flow logs')
        }
        
    except Exception as e:
        print(f"Error processing flow logs: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def extract_features(flow_record):
    """Extract relevant features from flow log record"""
    return {
        'bytes': int(flow_record.get('bytes', 0)),
        'packets': int(flow_record.get('packets', 0)),
        'protocol': int(flow_record.get('protocol', 0)),
        'action': flow_record.get('action', ''),
        'duration': int(flow_record.get('duration', 0))
    }

def update_waf_rules(wafv2_client, ip_address):
    """Update WAF rules to block malicious IP"""
    try:
        # Get current IP set
        response = wafv2_client.get_ip_set(
            Name='BlockList',
            Scope='REGIONAL',
            Id='your-ip-set-id'
        )
        
        # Add new IP to the set
        current_ips = response['IPSet']['Addresses']
        current_ips.append(f"{ip_address}/32")
        
        # Update IP set
        wafv2_client.update_ip_set(
            Name='BlockList',
            Scope='REGIONAL',
            Id='your-ip-set-id',
            Addresses=current_ips,
            LockToken=response['LockToken']
        )
        
    except Exception as e:
        print(f"Error updating WAF rules: {str(e)}")
        raise 