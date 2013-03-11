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

from django.core.exceptions import ValidationError

from lxml import etree
import StringIO
import sys, traceback
import OpenSSL

#Form validation for XML RID Messages
def RidMessageValidator(value):
	xml_string = value
	local_parser = etree.XMLParser(no_network=True)
	rid_schema_location = '/var/www/RID_Agent/RID_Agent/static/xsd/iodef-rid-2.0.xsd'
	
	try:
		xml_doc = etree.parse(StringIO.StringIO(xml_string), parser=local_parser)
	except:
		raise ValidationError(u'XML is not well formed. Error: %s.' % local_parser.error_log.last_error)
	
	try:
		schema_doc = etree.parse(rid_schema_location, parser=local_parser)
		rid_schema = etree.XMLSchema(schema_doc)
		valid = rid_schema.validate(xml_doc)
		if not valid:
			raise ValidationError(u'XML is not schema valid. Error: %s.' % rid_schema.error_log.last_error)
	except ValidationError:
		raise
	except:
		raise ValidationError(u'Schema validation error: %s.' % local_parser.error_log.last_error)
	pass


#Validate that the certificate is a valid certificate
def CertificateValidator(string_value):
	try:
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, string_value)
		x509.get_subject().get_components()
		pass
	except Exception as e:
		raise ValidationError(u'Certificate not a valid PEM x509 certificate: %s' % e)
