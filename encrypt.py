import boto3
from io import BytesIO
from botocore.exceptions import NoCredentialsError
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
import os
import json


# Create S3 and KMS clients
s3 = boto3.client('s3', region_name='ap-southeast-2')  # Replace with your region
kms = boto3.client('kms', region_name='ap-southeast-2') # Replace with your region

kms_key_id = 'arn:aws:kms:ap-southeast-2:253722483539:key/e44d1d6f-b242-4f5a-a02f-285957fe2f17'  # Replace with your KMS key ID

def generate_data_key(kms_client, key_id):
    response = kms_client.generate_data_key(KeyId=key_id, KeySpec='AES_256')
    return response['CiphertextBlob'], response['Plaintext']

# Specify S3 bucket and file to read
s3_bucket_name = 'kms-demo-bucket-encryption'  # Replace with your bucket name
s3_file_key = 'annual-enterprise-survey-2021-financial-year-provisional-csv.csv'  # Replace with the actual file key
s3_prefix = 'data'


# Download the file from S3
file_obj = s3.get_object(Bucket=s3_bucket_name, Key=s3_file_key)['Body']
file_data = file_obj.read()

# Generate data key and encrypt the data
encrypted_dek, plaintext_dek = generate_data_key(kms, kms_key_id)
iv = urandom(16)
cipher = Cipher(algorithms.AES(plaintext_dek), modes.CFB8(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(file_data) + encryptor.finalize()

# Create a control file
control_content = {
    'filename': f'{s3_file_key}.encrypted',
    'business_date': datetime.now().strftime('%Y-%m-%d'),
    'size': len(file_data),
    'iv': iv.hex(),
    'encrypted_data_key': encrypted_dek.hex()
}
control_path = f'{s3_file_key}.json'

with open(control_path, 'w') as control_file:
    json.dump(control_content, control_file)

# Upload encrypted file and control file to S3
s3.upload_fileobj(
    BytesIO(encrypted_data),
    s3_bucket_name,
    f'{s3_prefix}/{s3_file_key}.encrypted'
)

print(f"Encrypted data file '{s3_file_key}.encrypted' uploaded to S3.")

s3.upload_file(
    control_path,
    s3_bucket_name,
    f'{s3_prefix}/{control_path}'
)

os.remove(control_path)

print(f"Control file '{control_path}' uploaded to S3.")

print("Encryption and upload completed.")
