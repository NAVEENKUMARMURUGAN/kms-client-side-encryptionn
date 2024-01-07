import boto3
import json
from io import BytesIO
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
kms_client = boto3.client('kms', region_name='ap-southeast-2')  # Replace 'your-region' with the appropriate AWS region

def main():
    try:
        s3_bucket = 'kms-demo-bucket-encryption'
        s3_key = 'data/annual-enterprise-survey-2021-financial-year-provisional-csv.csv.json'

        control_file_data = fetch_control_file_data(s3_bucket, s3_key)

        decrypted_data = decrypt_data(control_file_data, s3_bucket)

        # Put the decrypted data back to S3
        decrypted_s3_key = f'decrypted/{control_file_data["filename"]}'.replace('encrypted','decrypted')
        put_decrypted_data_to_s3(s3_bucket, decrypted_s3_key, decrypted_data)

        logger.info("Application executed successfully!")
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f'Error: {str(e)}')

def fetch_control_file_data(s3_bucket, s3_key):
    try:
        control_file_content = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)['Body'].read()
        control_file_data = json.loads(control_file_content)
        logger.info("Control file data: %s", control_file_data)
        return control_file_data
    except Exception as e:
        logger.error(f"Error fetching S3 object: {e}")
        raise e

def decrypt_data(control_file_data, s3_bucket):
    try:
        encrypted_file_key = bytes.fromhex(control_file_data['encrypted_data_key'])
        iv = bytes.fromhex(control_file_data['iv'])

        decrypted_data_key = kms_client.decrypt(CiphertextBlob=encrypted_file_key)['Plaintext']

        encrypted_data_file = s3_client.get_object(Bucket=s3_bucket, Key=f'data/{control_file_data["filename"]}')
        encrypted_data = encrypted_data_file['Body'].read()

        cipher = Cipher(algorithms.AES(decrypted_data_key), modes.CFB8(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        return decrypted_data
    except Exception as e:
        logger.error(f"Error in decrypt_data: {e}")
        raise e

def put_decrypted_data_to_s3(s3_bucket, s3_key, decrypted_data):
    try:
        s3_client.put_object(Body=decrypted_data, Bucket=s3_bucket, Key=s3_key)
    except Exception as e:
        logger.error(f"Error putting decrypted data to S3: {e}")
        raise e

if __name__ == "__main__":
    main()
