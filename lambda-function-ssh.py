import json
import boto3
import base64
import paramiko
from botocore.exceptions import ClientError

def lambda_handler(context, event):
    
    ### Create sts session and credentials file ###

    sts_connection = boto3.client('sts')
    acct_b = sts_connection.assume_role(
        DurationSeconds=3600,
        RoleArn="ARN",
        RoleSessionName="cross_acct_lambda"
    )
    
    ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
    SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
    SESSION_TOKEN = acct_b['Credentials']['SessionToken']
    
    f = open("/tmp/credentials", "w")
    f.write("[default]" + '\n')
    f.write("aws_access_key_id = " + ACCESS_KEY + '\n')
    f.write("aws_secret_access_key = " + SECRET_KEY + '\n')
    f.write("aws_session_token = " + SESSION_TOKEN)
    f.close()
    
    f = open("/tmp/config", "w")
    f.write("[default]" + '\n')
    f.write("region = us-east-1")
    f.close()
    
    # print credentials file
    #f = open("/tmp/credentials", "r")
    #print(f.read())
    
    
    ### Retrieve ssh credentials ###
    
    secret_name = "ssh_creds"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print(e)
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            
    
    print(type(secret))
    
    output = json.loads(secret)
    #print(output['UserName'])
    #print(output['Password'])
    
    USERNAME_GET = (output['UserName'])
    PASSWORD_GET = (output['Password'])

    ### Copy credentials file to server
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname='IP',username=USERNAME_GET,password=PASSWORD_GET,port=22)
    sftp_client=ssh.open_sftp()
    
    sftp_client.put('/tmp/credentials','/home/user/.aws/credentials')
    sftp_client.put('/tmp/config','/home/user/.aws/config')
    
    sftp_client.close()
    ssh.close()
