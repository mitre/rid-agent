######################################################################################
#                                                                                    #
# Copyright (C) 2012-2013 - The MITRE Corporation. All Rights Reserved.              #
#                                                                                    #
# By using the software, you signify your aceptance of the terms and                 #
# conditions of use. If you do not agree to these terms, do not use the software.    #
#                                                                                    #
# For more information, please refer to the license.txt file.                        #
#                                                                                    #
######################################################################################

from django.http import HttpResponse
from models import incoming_message, outgoing_message, certificate
from datetime import datetime
from lxml import etree
import base64
import cgi
import sys
import os
import re
import string
import httplib, urllib, socket, ssl
import StringIO
import settings
import traceback

#Determines whether an XML file is valid against the supplied schema.
#Returns True or False, plus a message. The message is safe for output
#to a browser.
def IsXmlValid(schema_location, xml_doc):
	local_parser = etree.XMLParser(no_network=True)
	try:
		schema_doc = etree.parse(schema_location, parser=local_parser)
		xml_schema = etree.XMLSchema(schema_doc)
		valid = xml_schema.validate(xml_doc)
		if(valid):
			return True, 'OK'
		else:
			return False, xml_schema.error_log.last_error
	except:
		return False, local_parser.error_log.last_error#"There was an unexpected error parsing the XML document"

#Determines whether or not an XML document is a schema-valid RID document.
#A possible enhancement is to make the schema location a variable rather than
#hard coded.
def IsValidRid(xml_doc):
	schema_valid, message = IsXmlValid('/var/www/RID_Agent/RID_Agent/static/xsd/iodef-rid-2.0.xsd',
					   xml_doc)
	return schema_valid, message

#This retrieves the RID Message type from a RID XML Document
def GetRidMessageType(rid_xml_doc):
	ns_dict = {'iodef-rid': 'urn:ietf:params:xml:ns:iodef-rid-2.0'}
	msgtype_xpath = '/iodef-rid:RID/iodef-rid:RIDPolicy/@MsgType'
	try:
		msg_type = rid_xml_doc.xpath(msgtype_xpath, namespaces=ns_dict)[0]
	except Exception as message:
		msg_type = message
	return msg_type

#This is a convenience method for getting the HTTP Client's
#IP address. It handles errors and such.
def GetRemoteIp(request):
	if request is None:
		return None
	x_header = request.META.get('HTTP_X_FORWARDED_FOR')
	if x_header:
		ip = x_header.split(',')[0]
	else:
		ip = request.META.get('REMOTE_ADDR')
	if ip is None:
		ip = 'Error getting IP address'
	return ip

#Returns True, and the XML if parsing succeeded
#Returns False, and an error message if the XML parsing failed
#This method does not do schema validation
def StringToXml(xml_string):
	local_parser = etree.XMLParser(no_network=True)
	try:
		xml_doc = etree.parse(StringIO.StringIO(xml_string), parser=local_parser)
		return True, xml_doc
	except:
		return False, local_parser.error_log.last_error #XML parse errors get raised here

#Sends a RID Message using the RID protocol.
def SendRidMessageToPeer(ip_dest, xml_string, use_https=True):
	try:
		custom_headers = {'Content-Type': 'text/xml',
				  'User-Agent': 'MITRE RID Agent (Unversioned)'}
		port = 4590
		if use_https:
			key_file = settings.KEY_FILE
			cert_file = settings.CERT_FILE
			conn = VerifiedHTTPSConnection(ip_dest, port, key_file, cert_file)
		else:
			conn = httplib.HTTPConnection(ip_dest, port)
		req = conn.request('POST', '/', xml_string, custom_headers)
		response = conn.getresponse()
		#200 is the only valid response for a Report
		#200 or 202 are valid responses for Query.
		#TODO: Make it so that a 202 for a Report does not mean success
		if response.status == 202 or response.status == 200:#These are the only two valid response codes
			return 'True', response
		else:
			return 'False', response
	except Exception as message:
		stack_trace = StringIO.StringIO()
		traceback.print_exc(file=stack_trace)
		return 'Error', stack_trace.getvalue()


#This is a covenience function for saving an incoming message to the database
def SaveIncomingMessage(src_ip, type, xml):
	try:
		i = incoming_message()
		i.source_ip = src_ip
		i.message_type = type
		i.status = "new"
		i.created = datetime.now()
		i.xml = xml
		i.json = "Nothing here yet"#An optional JSON representation. Not implemented
		i.save()
		return True, str(i.id)
	except Exception as message:
		return False, str(message)

#Saves an outgoing message to the database.
#Note: There is currently not any code to actually do anything
#      with messages saved in this manner
def SaveOutgoingMessage(dest_ip, incoming_message_id, xml_string):
	o = outgoing_message()
	o.created = datetime.now()
	o.ip_destination = dest_ip
	o.xml = xml_string
	if incoming_message_id is not None:
		o.incoming_message_id = incoming_message_id
	o.status = 'new'
	o.save()
	return True, o.id

#Convenience method to take the result of a query and turn it into
#XML.
def IncomingMessagesToXml(messages):
	xml = "<messages count=\"" + str(messages.count()) + "\">"
	for message in messages:
		xml += "<message "
		xml += "id=\"" + str(message.id) + "\" "
		xml += "source_ip=\"" + message.source_ip + "\" "
		xml += "message_type=\"" + message.message_type + "\" "
		xml += "created=\"" + str(message.created) + "\" "
		xml += "response_id=\"" + str(message.response_id) + "\" "
		xml += ">"
		xml += message.xml
		xml += "</message>"
	xml += "</messages>"
	return xml

#TODO: This needs a lot more work, but it satisfies basic functionality for now.
def GetLogs(log_view_form=None):
	log_level_regex = '(DEBUG|INFO|WARNING|ERROR|CRITICAL)'
	if log_view_form is not None:
		levels = ['debug','info','warning','error','critical','exception']
		tmp_regex = '('
		for level in levels:
			if log_view_form[level].value() == 'on':
				tmp_regex += (string.upper(level) + '|')
		if string.rfind(tmp_regex, '|') == len(tmp_regex) -1:#The last char is a pipe, meaning at least one log level was selected
			log_level_regex = tmp_regex[:len(tmp_regex)-1] + ')'
	
	log_file = open('/var/www/RID_Agent/RID_Agent/logs/rid_application_log.log')
	return_data = 'Regex: ' + log_level_regex + '\n'
	for line in log_file:
		if(re.search(log_level_regex, line) is not None):
			return_data += line
	return return_data

def get_api_10_response(values_dict):
	if 'type' not in values_dict or 'message' not in values_dict:
		raise Exception('Required items not in dict. ' + str(values_dict.keys()))
	
	body = '<api_response type="' 
	body +=	values_dict['type'] + '" '
	body +=	'message="'  
	body +=	values_dict['message'] + '">'
	
	if 'content' in values_dict:
		body += '\n'
		body += values_dict['content'] + '\n'
	
	body += '</api_response>'
	resp = HttpResponse(body)
	resp['Content-Type'] = 'text/xml'
	if 'status_code' in values_dict:
		resp.status_code = int(values_dict['status_code'])
	return resp

###################################
###END API 1.0 Function Calls######
###################################


#The default httplib HTTPSConnection does not verify certificates.
#This class extends HTTPSConnection and requires certificate verification.
#Borrowed from http://thejosephturner.com/blog/2011/03/19/https-certificate-verification-in-python-with-urllib2/
class VerifiedHTTPSConnection(httplib.HTTPSConnection):
	def connect(self):
		#overrides the version in httplib so that we do 
		#certificate verification
		sock = socket.create_connection((self.host, self.port), self.timeout)
		if self._tunnel_host:
			self.sock = sock
			self._tunnel()
		#wrap the socket using verification with the root
		#certs in trusted_root_certs
		self.sock = ssl.wrap_socket(sock,
					    self.key_file,
					    self.cert_file,
					    cert_reqs=ssl.CERT_REQUIRED,
					    ca_certs='/var/www/RID_Agent/RID_Agent/client_certs/cacerts.crt')

