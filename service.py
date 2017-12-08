# -*- coding: utf-8 -*-
import os
from xero import Xero
from xero.auth import PrivateCredentials
from xero.exceptions import XeroNotFound
from datetime import datetime
from dateutil.parser import parse
import hashlib
import hmac
import base64
import json

with open('./keys/lambdaprivatekey.pem') as keyfile:
	rsa_key = keyfile.read()

credentials = PrivateCredentials(os.getenv("XERO_CONSUMER_KEY_WEBHOOKS"), rsa_key)
xero = Xero(credentials)


def intent_to_receive_check(body, xero_signature):
	# Convert the our webhooks key to bytes with utf-8 encoding.
	webhooks_key = bytes(os.getenv("XERO_WEBHOOK_KEY"), 'utf-8')
	# Convert the request of the body to bytes with utf-8 encoding.
	body = bytes(body, 'utf-8')

	# HMAC SHA-256 sign the body with our Xero webhooks key
	hash = hmac.new(webhooks_key, body, hashlib.sha256)

	# Base64 encode the HMAC hash
	response_signature = base64.b64encode(hash.digest()).decode('utf-8')
	
	# Compare the body (HMAC signed & Base64 encoded) to the signature provided
	if response_signature == xero_signature:
		return True
	else:
		return False

def find_file_by_name(attachments, filename):
	# are there any attachments?
	if attachments:
		# loop through them
		for attachment in attachments:
			# check if the file exists and return
			if attachment['FileName'] == filename:
				return True
	
	# no attachment found by this name, return false
	return False


def handler(event, context):
	# Your code goes here!
	headers = event.get('headers')
	body = json.loads(event.get('body'))
	
	# Handle ITR - Intent to Receive
	# ITR response must be a response code ONLY, it will complain if the response has a body.
	if body['firstEventSequence'] == body['lastEventSequence'] == 0:
		if intent_to_receive_check(event.get('body'), headers['x-xero-signature']):
			return { "statusCode": 200 }
		else:
			return { "statusCode": 401 }

	# We've completed the ITR, lets do something with a webhook
	for event in body["events"]:
		# check it's an invoice
		if event['eventCategory'] == "INVOICE":
			# Lets create an attachment against the invoice. The attachment will contain the webhook event request.
			# First lets format the eventDateUtc into a string we can use as a file name
			event_timestamp = parse(event['eventDateUtc']).strftime('%s')
			filename = event_timestamp+'.txt'

			# Lets retrieve the existing attachments
			attachments_response = xero.invoices.get_attachments(event['resourceId'])
			# Check that this attachment does not already exist (we could have received this webhook request already)
			if not find_file_by_name(attachments_response['Attachments'], filename):
				# Create the event response as a text file and write to disk
				file = open('/tmp/'+filename, 'w')
				file.write(str(event))
				file.close()
				
				# Now lets attach it to the Xero Invoice via the Xero API
				file = open('/tmp/'+filename, 'r')
				xero.invoices.put_attachment(event['resourceId'], filename, file, 'text/plain')
				file.close()

	# Return 200.  Note: Xero Webhook responses should return ONLY a HTTP code.
	# Any response containing a body will be considered an error, and the webhook event will be repeated.
	# If the webhook responses continue to error, webhook requests will back off, until they are eventually deactivated.
	return { "statusCode": 200 }










