__author__ = 'Nispand'
# import statements
import argparse
import httplib2
import os
import sys
import json
import time
import datetime
import io
import hashlib
# Google apliclient (Google App Engine specific) libraries
from apiclient import discovery
from oauth2client import file
from oauth2client import client
from oauth2client import tools
from googleapiclient.http import MediaIoBaseDownload
# pycry#pto libraries

from Crypto import Random
from Crypto.Cipher import AES

# Initial password to create a key
password = 'googlecloud'
# key to use
key = hashlib.sha256(password).digest()

# this implementation of AES works on blocks of "text",put "0"s at the end if too small.

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def encrypt(message, key, key_size=256):
    message = pad(message)
    print AES.block_size
    # iv is initialization vector
    iv = Random.new().read(AES.block_size)
    print len(iv)
    # encrypt entire message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


# Function to decrypt the message
def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")


# Function to encrypt a give file
def encrypt_file(file_name, key):
    # Open file to read content in the file,encrypt the file data and
    # create a new file and then write the encrypted to it,return the encrypted file name.
    f1 = open(file_name, 'rb')
    s = f1.read()
    f1.close()
    e = encrypt(s, key)
    f2 = open(file_name, 'wb')
    f2.write(e)
    return f2.name


# Function to decrypt a given file
def decrypt_file(file_name, key):
    # Opend file to read the data of the file,decrypt the file data and
    # create a new file and then write the decrypted data to the file
    fn = open(file_name, 'rb')
    s = fn.read()
    fn.close()
    d = decrypt(s, key)
    fx = open(file_name, 'wb')
    fx.write(d)
    return fx.name



_BUCKET_NAME = 'cloud_project'  # name of the bucket
_API_VERSION = 'v1'

# Parser for command line arguments.
parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    parents=[tools.argparser])

# client_secret.json is the JSON file that contains the client ID and secret.

CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secret.json')

# setup a flow object to be used for authentication
# Add one or more of the following scopes.
# These scopes are used to restrict the user to only specified permissions (in this case only to devstorage)

FLOW = client.flow_from_clientsecrets(CLIENT_SECRETS, scope=[
    'https://www.googleapis.com/auth/devstorage.full_control',
    'https://www.googleapis.com/auth/devstorage.read_only',
    'https://www.googleapis.com/auth/devstorage.read_write',
],
                                      message=tools.message_if_missing(CLIENT_SECRETS))

# Downloas the specified object from the given bucket and deletes it from the bucket.

def get(service):
    # User can be prompted to input file name(using raw_input) that needs to be be downloaded.
    file_name = raw_input("Enter file name to be downloaded:")
    try:
        # Get Metadata
        req = service.objects().get(
            bucket=_BUCKET_NAME,
            object=file_name,
            fields='bucket,name,metadata(my-key)',

        )
        resp = req.execute()
        print json.dumps(resp, indent=2)
        # Get Payload Data
        req = service.objects().get_media(
            bucket=_BUCKET_NAME,
            object=file_name,
        )
        # The Bytes I/O object may be replaced with any io.Base instance.
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, req, chunksize=1024 * 1024)  # show progress at download
        done = False
        while not done:
            status, done = downloader.next_chunk()
            if status:
                print 'Download %d%%.' % int(status.progress() * 100)
            print 'Download Complete'

        fo = decrypt(fh.getvalue(),key)
        fi = open(file_name,'wb')
        fi.write(fo)
        # fh.getvalue() contains downloaded content.Decrypt the file and save it to onto your local machine
        print json.dumps(resp, indent=2)
    except client.AccessTokenRefreshError:
        print ("Error in the credentials")


        # Puts object into file after encryption and deletes the object from the local PC


def put(service):
    '''User puts the file_name that needs to be uploaded.
	   Encrypt the given file using AES Encryption
	   and then upload the file to your bucket on to the google cloud storage.
           Remove the file from your local machine after the upload. '''
    file_name = raw_input("Enter file name to be uploaded:")
    file_name = encrypt_file(file_name, key)
    try:
        # Get Metadata
        req = service.objects().insert(
            media_body = file_name,
            name = file_name,
            bucket = _BUCKET_NAME
        )
        resp = req.execute()
        print json.dumps(resp, indent=2)
        print '>Uploaded source file %s' % file_name
        os.remove(file_name)
        # fh.getvalue() contains downloaded content.Decrypt the file and save it to onto your local machine
    except client.AccessTokenRefreshError:
        print ("Error in the credentials")



# List all the objects from the objects from the given bucket name
def listobj(service):
    req = service.buckets().get(bucket=_BUCKET_NAME)
    resp = req.execute()
    fields_to_return = \
        'nextPageToken,items(name,size,contentType,metadata(my-key))'
    req = service.objects().list(bucket=_BUCKET_NAME, fields=fields_to_return)
    print "list of files in the current bucket are:"
    while req is not None:
        resp = req.execute()
        for object in resp["items"]:
            print object["name"],"\n"
        req = service.objects().list_next(req, resp)
    """List all the objects that are present inside the bucket."""


# This deleted the object from the bucket
def deleteobj(service):
    """Prompt the user to enter the name of the object to be deleted from your bucket."""
    file_name = raw_input("Enter the name of the file to be deleted:")
    service.objects().delete(bucket=_BUCKET_NAME,object=file_name).execute()


# Pass the object name to the delete() method to remove the object from yout bucket




def main(argv):
    # Parse the command-line flags.
    flags = parser.parse_args(argv[1:])

    # sample.dat file stores the short lived access tokens,which your application requests user data, attaching the access token to the request.
    # so that user need tnot validate through the browser everytime.This is optional.If the credentials don't exist
    # or are invalid run through the native client flow.The storage object will ensure that if successfull the good
    # credentials will get written back to the file(sample.dat in this case).

    storage = file.Storage('sample.dat')
    credentials = storage.get()
    if credentials is None or credentials.invalid:
        credentials = tools.run_flow(FLOW, storage, flags)

    # create an httplib2.Http object to handle our HTTP requests and authorize it.
    # with our good credentials
    http = httplib2.Http()
    http = credentials.authorize(http)

    # construct the service object for the interaction with the cloud storage api
    service = discovery.build('storage', _API_VERSION, http=http)

    # this is kind of switch equivalent in C or Java
    # store the option and name of the function as the key value pair in the dictionary

    options = {1: put, 2: get, 3: listobj, 4: deleteobj}

    option = raw_input("Enter your option:")

    options[int(option)](service)


if __name__ == '__main__':
    main(sys.argv)

# ENDALL
