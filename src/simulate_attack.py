import boto3
import time
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import random
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_alb_dns():
    """Get the ALB DNS name"""
    elbv2 = boto3.client('elbv2')
    try:
        response = elbv2.describe_load_balancers(Names=['ai-firewall-alb'])
        return response['LoadBalancers'][0]['DNSName']
    except Exception as e:
        logging.error(f"Error getting ALB DNS: {str(e)}")
        return None

def simulate_http_flood():
    """Simulate HTTP flood attack with suspicious signatures"""
    dns_name = get_alb_dns()
    if not dns_name:
        logging.error("Could not get ALB DNS name")
        return
    
    base_url = f"http://{dns_name}"
    paths = [
        '/login?test=true',
        '/admin?test=true&action=delete',
        '/test?test=true&debug=1',
        '/check?test=true&verify=admin',
        '/user?test=true&verify=admin'
    ]
    
    # Track metrics for NIDS analysis
    request_metrics = {
        'total_requests': 0,
        'response_codes': {},
        'unique_ips': set(),
        'request_intervals': [],
        'path_counts': {},
        'start_time': time.time()
    }
    
    def send_requests():
        last_request_time = time.time()
        for _ in range(2):  # Reduced to 2 requests per thread
            path = random.choice(paths)
            url = base_url + path
            try:
                # Generate random source IP
                source_ip = f'192.168.{random.randint(1,255)}.{random.randint(1,255)}'
                headers = {
                    'X-Forwarded-For': source_ip,
                    'User-Agent': random.choice([
                        'Mozilla/5.0',
                        'Python-requests/2.25.1',
                        'curl/7.64.1'
                    ])
                }
                
                # Record request timing
                current_time = time.time()
                interval = current_time - last_request_time
                request_metrics['request_intervals'].append(interval)
                last_request_time = current_time
                
                # Track path usage
                request_metrics['path_counts'][path] = request_metrics['path_counts'].get(path, 0) + 1
                
                # Send request and record metrics
                response = requests.get(url, headers=headers, timeout=5)
                request_metrics['total_requests'] += 1
                request_metrics['unique_ips'].add(source_ip)
                
                status_code = str(response.status_code)
                request_metrics['response_codes'][status_code] = request_metrics['response_codes'].get(status_code, 0) + 1
                
                logging.info(f"Request to {path}: {response.status_code}")
            except Exception as e:
                logging.info(f"Request failed: {str(e)}")
            time.sleep(3)  # Increased delay between requests to 3 seconds
    
    logging.info(f"Starting HTTP flood simulation to {base_url}")
    with ThreadPoolExecutor(max_workers=1) as executor:  # Reduced to 1 worker
        executor.submit(send_requests)
    
    # Calculate metrics for NIDS analysis
    elapsed_time = time.time() - request_metrics['start_time']
    request_rate = request_metrics['total_requests'] / elapsed_time
    avg_interval = sum(request_metrics['request_intervals']) / len(request_metrics['request_intervals']) if request_metrics['request_intervals'] else 0
    
    # Log detailed metrics
    logging.info("\nDetailed Request Metrics for NIDS Analysis:")
    logging.info(f"Total Requests: {request_metrics['total_requests']}")
    logging.info(f"Unique Source IPs: {len(request_metrics['unique_ips'])}")
    logging.info(f"Response Code Distribution: {request_metrics['response_codes']}")
    logging.info(f"Average Request Interval: {avg_interval:.2f} seconds")
    logging.info(f"Request Rate: {request_rate:.2f} requests/second")
    logging.info(f"Path Distribution: {request_metrics['path_counts']}")
    
    # Send metrics to CloudWatch for NIDS analysis
    cloudwatch = boto3.client('cloudwatch')
    
    # Basic metrics
    metric_data = [
        {
            'MetricName': 'RequestRate',
            'Value': request_rate,
            'Unit': 'Count/Second'
        },
        {
            'MetricName': 'UniqueIPs',
            'Value': len(request_metrics['unique_ips']),
            'Unit': 'Count'
        }
    ]
    
    # Response code metrics
    for code, count in request_metrics['response_codes'].items():
        metric_data.append({
            'MetricName': f'ResponseCode{code}',
            'Value': count,
            'Unit': 'Count'
        })
    
    # Send metrics in batches to stay under API limits
    for i in range(0, len(metric_data), 20):  # CloudWatch accepts max 20 metrics per call
        batch = metric_data[i:i+20]
        cloudwatch.put_metric_data(
            Namespace='AIFirewall/NIDS',
            MetricData=batch
        )
        time.sleep(0.5)  # Small delay between batches
    
    logging.info("HTTP flood simulation completed")

def simulate_syn_flood():
    """Simulate SYN flood metrics"""
    print("Starting SYN flood simulation (metrics only)")
    cloudwatch = boto3.client('cloudwatch')
    
    # Get ALB ARN
    elbv2 = boto3.client('elbv2')
    try:
        response = elbv2.describe_load_balancers(Names=['ai-firewall-alb'])
        alb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
        alb_name = alb_arn.split('/')[-1]
        
        # Track SYN flood metrics
        syn_metrics = {
            'total_syns': 0,
            'syn_rate': 0,
            'start_time': time.time()
        }
        
        # Send metrics for 15 seconds
        for i in range(1):  # Reduced to 1 iteration
            syn_count = random.randint(10, 30)  # Reduced values
            syn_metrics['total_syns'] += syn_count
            
            cloudwatch.put_metric_data(
                Namespace='AIFirewall/NIDS',
                MetricData=[
                    {
                        'MetricName': 'TCP_SYN_Count',
                        'Value': syn_count,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'LoadBalancer',
                                'Value': alb_name
                            }
                        ]
                    }
                ]
            )
            print(f"Sent SYN flood metrics {i+1}/1")
            time.sleep(10)  # Increased delay between metrics
        
        # Calculate and send rate metrics
        elapsed_time = time.time() - syn_metrics['start_time']
        syn_metrics['syn_rate'] = syn_metrics['total_syns'] / elapsed_time
        
        cloudwatch.put_metric_data(
            Namespace='AIFirewall/NIDS',
            MetricData=[
                {
                    'MetricName': 'SYN_Rate',
                    'Value': syn_metrics['syn_rate'],
                    'Unit': 'Count/Second'
                }
            ]
        )
        
        print("\nSYN Flood Metrics:")
        print(f"Total SYNs: {syn_metrics['total_syns']}")
        print(f"SYN Rate: {syn_metrics['syn_rate']:.2f} per second")
        print(f"Duration: {elapsed_time:.1f} seconds")
        
    except Exception as e:
        print(f"Error in SYN flood simulation: {str(e)}")

def simulate_api_abuse():
    """Simulate API abuse with rate limiting evasion attempts"""
    dns_name = get_alb_dns()
    if not dns_name:
        logging.error("Could not get ALB DNS name")
        return
    
    base_url = f"http://{dns_name}"
    api_paths = [
        '/api/v1/users?page=1&size=1000',  # Large page size
        '/api/v1/search?q=*',              # Wildcard search
        '/api/v1/export?format=csv',       # Resource-intensive operation
        '/api/v1/auth/login',              # Auth endpoint
    ]
    
    for _ in range(2):  # Limited number of attempts
        path = random.choice(api_paths)
        url = base_url + path
        try:
            headers = {
                'X-Forwarded-For': f'192.168.{random.randint(1,255)}.{random.randint(1,255)}',
                'User-Agent': 'APIClient/1.0',
                'Authorization': 'Bearer invalid_token_test'
            }
            response = requests.get(url, headers=headers, timeout=5)
            logging.info(f"API abuse test to {path}: {response.status_code}")
        except Exception as e:
            logging.info(f"API request failed: {str(e)}")
        time.sleep(3)  # Delay between requests

def simulate_path_traversal():
    """Simulate path traversal and LFI attempts"""
    dns_name = get_alb_dns()
    if not dns_name:
        return
    
    base_url = f"http://{dns_name}"
    paths = [
        '/static/../../../etc/passwd',
        '/images/..%2f..%2f..%2f/windows/win.ini',
        '/include/../../../../../../../../etc/hosts',
        '/api/v1/files/../../config.json'
    ]
    
    for _ in range(2):  # Limited attempts
        path = random.choice(paths)
        url = base_url + path
        try:
            headers = {
                'User-Agent': 'SecurityTest/1.0',
                'Accept': '*/*'
            }
            response = requests.get(url, headers=headers, timeout=5)
            logging.info(f"Path traversal test to {path}: {response.status_code}")
        except Exception as e:
            logging.info(f"Path traversal request failed: {str(e)}")
        time.sleep(3)

def simulate_sql_injection():
    """Simulate SQL injection attempts"""
    dns_name = get_alb_dns()
    if not dns_name:
        return
    
    base_url = f"http://{dns_name}"
    payloads = [
        '/api/users?id=1 OR 1=1',
        '/api/search?q=test\' UNION SELECT * FROM users--',
        '/api/login?username=admin\'--&password=test',
        '/api/products?category=1\' OR \'1\'=\'1'
    ]
    
    for _ in range(2):  # Limited attempts
        payload = random.choice(payloads)
        url = base_url + payload
        try:
            headers = {
                'User-Agent': 'TestClient/1.0',
                'Content-Type': 'application/json'
            }
            response = requests.get(url, headers=headers, timeout=5)
            logging.info(f"SQL injection test to {payload}: {response.status_code}")
        except Exception as e:
            logging.info(f"SQL injection request failed: {str(e)}")
        time.sleep(3)

def simulate_nosql_injection():
    """Simulate NoSQL injection attempts"""
    dns_name = get_alb_dns()
    if not dns_name:
        return
    
    base_url = f"http://{dns_name}"
    endpoints = ['/api/v1/users/find', '/api/v1/auth', '/api/v1/data']
    
    for _ in range(2):  # Limited attempts
        endpoint = random.choice(endpoints)
        url = base_url + endpoint
        try:
            # NoSQL injection payloads
            payloads = [
                {"username": {"$ne": null}},
                {"password": {"$exists": true}},
                {"$where": "sleep(100)"}
            ]
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'NoSQLTest/1.0'
            }
            response = requests.post(url, json=random.choice(payloads), headers=headers, timeout=5)
            logging.info(f"NoSQL injection test to {endpoint}: {response.status_code}")
        except Exception as e:
            logging.info(f"NoSQL injection request failed: {str(e)}")
        time.sleep(3)

def send_metrics_to_cloudwatch(metrics, namespace='AIFirewall/NIDS'):
    """Send metrics to CloudWatch"""
    try:
        cloudwatch = boto3.client('cloudwatch')
        metric_data = []
        
        for name, value in metrics.items():
            metric_data.append({
                'MetricName': name,
                'Value': value,
                'Unit': 'Count'
            })
        
        if metric_data:
            cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=metric_data
            )
            time.sleep(0.5)  # Delay between CloudWatch API calls
    except Exception as e:
        logging.error(f"Error sending metrics to CloudWatch: {str(e)}")

def main():
    try:
        logging.info("Starting new attack simulation patterns...")
        
        # Track overall metrics
        attack_metrics = {
            'APIAbuseAttempts': 0,
            'PathTraversalAttempts': 0,
            'SQLInjectionAttempts': 0,
            'NoSQLInjectionAttempts': 0,
            'TotalRequests': 0
        }
        
        # Run different attack simulations
        logging.info("Simulating API abuse...")
        simulate_api_abuse()
        attack_metrics['APIAbuseAttempts'] += 2
        
        logging.info("Simulating path traversal...")
        simulate_path_traversal()
        attack_metrics['PathTraversalAttempts'] += 2
        
        logging.info("Simulating SQL injection...")
        simulate_sql_injection()
        attack_metrics['SQLInjectionAttempts'] += 2
        
        logging.info("Simulating NoSQL injection...")
        simulate_nosql_injection()
        attack_metrics['NoSQLInjectionAttempts'] += 2
        
        attack_metrics['TotalRequests'] = sum([
            attack_metrics['APIAbuseAttempts'],
            attack_metrics['PathTraversalAttempts'],
            attack_metrics['SQLInjectionAttempts'],
            attack_metrics['NoSQLInjectionAttempts']
        ])
        
        # Send final metrics to CloudWatch
        logging.info("Sending metrics to CloudWatch...")
        send_metrics_to_cloudwatch(attack_metrics)
        
        logging.info("\nAttack Simulation Summary:")
        for metric, value in attack_metrics.items():
            logging.info(f"{metric}: {value}")
        
        logging.info("\nWaiting 30 seconds for metrics to be available...")
        time.sleep(30)
        logging.info("Attack simulation completed")
        
    except Exception as e:
        logging.error(f"Error in attack simulation: {str(e)}")

if __name__ == '__main__':
    main() 