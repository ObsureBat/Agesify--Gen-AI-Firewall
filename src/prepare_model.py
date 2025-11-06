import boto3
import json
import os
import tensorflow as tf
import joblib
import shutil
import tarfile

def prepare_model_for_sagemaker():
    """Prepare the model for SageMaker deployment"""
    # Load the model
    print("Loading model...")
    model = tf.keras.models.load_model('nids_model.h5')
    
    # Create model directory
    model_dir = 'model'
    if os.path.exists(model_dir):
        shutil.rmtree(model_dir)
    os.makedirs(os.path.join(model_dir, '1'))
    
    # Export model in SavedModel format
    print("Exporting model...")
    model.export(os.path.join(model_dir, '1'))
    
    # Copy scaler
    print("Copying scaler...")
    os.makedirs(os.path.join(model_dir, '1', 'variables'), exist_ok=True)
    joblib.dump(joblib.load('scaler.pkl'), os.path.join(model_dir, '1', 'variables', 'scaler.pkl'))
    
    # Create tar.gz archive
    print("Creating model archive...")
    with tarfile.open('model.tar.gz', 'w:gz') as tar:
        tar.add(model_dir, arcname=os.path.basename(model_dir))

def create_sagemaker_endpoint():
    """Create SageMaker endpoint for model inference"""
    print("Creating SageMaker endpoint...")
    
    # Upload model to S3
    print("Uploading model to S3...")
    account_id = boto3.client('sts').get_caller_identity()['Account']
    bucket_name = f'ai-firewall-models-{account_id}'
    s3 = boto3.client('s3')
    s3.upload_file('model.tar.gz', bucket_name, 'model.tar.gz')
    
    # Create SageMaker model
    print("Creating SageMaker model...")
    sagemaker = boto3.client('sagemaker')
    
    # Use the official AWS Deep Learning container for TensorFlow inference
    container_image = f'763104351884.dkr.ecr.us-east-1.amazonaws.com/tensorflow-inference:2.11.0-cpu'
    
    sagemaker.create_model(
        ModelName='ai-firewall-model',
        PrimaryContainer={
            'Image': container_image,
            'ModelDataUrl': f's3://{bucket_name}/model.tar.gz'
        },
        ExecutionRoleArn=f'arn:aws:iam::{account_id}:role/SageMakerExecutionRole'
    )
    
    # Create endpoint configuration
    print("Creating endpoint configuration...")
    sagemaker.create_endpoint_config(
        EndpointConfigName='ai-firewall-endpoint-config',
        ProductionVariants=[{
            'VariantName': 'AllTraffic',
            'ModelName': 'ai-firewall-model',
            'InstanceType': 'ml.t2.medium',
            'InitialInstanceCount': 1
        }]
    )
    
    # Create endpoint
    print("Creating endpoint...")
    sagemaker.create_endpoint(
        EndpointName='ai-firewall-endpoint',
        EndpointConfigName='ai-firewall-endpoint-config'
    )
    
    print("Waiting for endpoint to be ready...")
    waiter = sagemaker.get_waiter('endpoint_in_service')
    waiter.wait(EndpointName='ai-firewall-endpoint')

def main():
    """Main function to prepare and deploy the model"""
    try:
        print("Preparing model for SageMaker...")
        prepare_model_for_sagemaker()
        
        print("\nCreating SageMaker endpoint...")
        create_sagemaker_endpoint()
        
        print("\nModel preparation and deployment completed!")
        print("\nNext steps:")
        print("1. Wait for the endpoint to become active (may take 5-10 minutes)")
        print("2. Update the Lambda function with the endpoint name")
        print("3. Test the endpoint with sample traffic data")
        
    except Exception as e:
        print(f"Error during model preparation: {str(e)}")
        raise

if __name__ == '__main__':
    main() 