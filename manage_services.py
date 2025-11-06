import boto3
import argparse
import time
import json

class AWSServiceManager:
    def __init__(self):
        self.sagemaker = boto3.client('sagemaker')
        self.guardduty = boto3.client('guardduty')
        self.lambda_client = boto3.client('lambda')
        self.events = boto3.client('events')
        self.account_id = boto3.client('sts').get_caller_identity()['Account']
        self.region = boto3.session.Session().region_name

    def start_services(self):
        """Start all AWS services needed for the AI Firewall"""
        print("Starting AWS services...")

        # Enable GuardDuty
        try:
            print("Enabling GuardDuty...")
            self.guardduty.update_detector(
                DetectorId=self._get_detector_id(),
                Enable=True
            )
        except Exception as e:
            print(f"Error enabling GuardDuty: {str(e)}")

        # Start SageMaker endpoint
        try:
            print("Starting SageMaker endpoint...")
            self.sagemaker.start_endpoint(
                EndpointName='ai-firewall-endpoint'
            )
        except Exception as e:
            print(f"Error starting SageMaker endpoint: {str(e)}")

        # Enable Lambda trigger
        try:
            print("Enabling Lambda trigger...")
            self.events.enable_rule(
                Name='AIFirewallFlowLogsRule'
            )
        except Exception as e:
            print(f"Error enabling Lambda trigger: {str(e)}")

        print("All services started successfully!")

    def stop_services(self):
        """Stop all AWS services to stay within free tier"""
        print("Stopping AWS services...")

        # Disable GuardDuty
        try:
            print("Disabling GuardDuty...")
            self.guardduty.update_detector(
                DetectorId=self._get_detector_id(),
                Enable=False
            )
        except Exception as e:
            print(f"Error disabling GuardDuty: {str(e)}")

        # Stop SageMaker endpoint
        try:
            print("Stopping SageMaker endpoint...")
            self.sagemaker.stop_endpoint(
                EndpointName='ai-firewall-endpoint'
            )
        except Exception as e:
            print(f"Error stopping SageMaker endpoint: {str(e)}")

        # Disable Lambda trigger
        try:
            print("Disabling Lambda trigger...")
            self.events.disable_rule(
                Name='AIFirewallFlowLogsRule'
            )
        except Exception as e:
            print(f"Error disabling Lambda trigger: {str(e)}")

        print("All services stopped successfully!")

    def get_service_status(self):
        """Get the current status of all services"""
        print("Checking service status...")

        # Check GuardDuty
        try:
            detector_id = self._get_detector_id()
            detector = self.guardduty.get_detector(DetectorId=detector_id)
            print(f"GuardDuty Status: {'Enabled' if detector['Status'] == 'ENABLED' else 'Disabled'}")
        except Exception as e:
            print(f"Error checking GuardDuty status: {str(e)}")

        # Check SageMaker endpoint
        try:
            endpoint = self.sagemaker.describe_endpoint(
                EndpointName='ai-firewall-endpoint'
            )
            print(f"SageMaker Endpoint Status: {endpoint['EndpointStatus']}")
        except Exception as e:
            print(f"Error checking SageMaker endpoint status: {str(e)}")

        # Check Lambda trigger
        try:
            rule = self.events.describe_rule(
                Name='AIFirewallFlowLogsRule'
            )
            print(f"Lambda Trigger Status: {rule['State']}")
        except Exception as e:
            print(f"Error checking Lambda trigger status: {str(e)}")

    def _get_detector_id(self):
        """Get GuardDuty detector ID"""
        detectors = self.guardduty.list_detectors()
        if not detectors['DetectorIds']:
            raise Exception("No GuardDuty detector found")
        return detectors['DetectorIds'][0]

def main():
    parser = argparse.ArgumentParser(description='Manage AWS services for AI Firewall')
    parser.add_argument('action', choices=['start', 'stop', 'status'], 
                      help='Action to perform (start/stop/status)')
    args = parser.parse_args()

    manager = AWSServiceManager()

    if args.action == 'start':
        manager.start_services()
    elif args.action == 'stop':
        manager.stop_services()
    else:
        manager.get_service_status()

if __name__ == '__main__':
    main() 