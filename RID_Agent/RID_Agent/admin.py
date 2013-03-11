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

from django.contrib import admin
import forms
from RID_Agent.models import incoming_message, outgoing_message, certificate, user_profile

# These are the admin classes.
# More info: https://docs.djangoproject.com/en/dev/ref/contrib/admin/

class IncomingMessageAdmin(admin.ModelAdmin):
	list_display = ['id', 'source_ip', 'message_type', 'created', 'response_id', 'xml', 'json']
	pass

class UserProfile(admin.ModelAdmin):
	list_display = ['user','rid_user','rid_peer','rid_backend']
	pass

class OutgoingMessageAdmin(admin.ModelAdmin):
	list_display = ['id','ip_destination','xml','incoming_message_id','status','sent_time']
	pass

class CertificateAdmin(admin.ModelAdmin):
	list_display = ['id', 'title', 'subject', 'issuer', 'description', 'cert']
	
	def cert(self, obj):
		return '<pre>%s</pre>' % obj.pem_certificate
	
	cert.allow_tags = True
	
	pass

admin.site.register(incoming_message, IncomingMessageAdmin)
admin.site.register(outgoing_message, OutgoingMessageAdmin)
admin.site.register(certificate, CertificateAdmin)
admin.site.register(user_profile, UserProfile)
