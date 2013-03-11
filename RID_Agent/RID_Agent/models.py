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

from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save, pre_save, post_delete
from django.core.validators import MaxLengthValidator, validate_ipv46_address, RegexValidator
import validators
import OpenSSL

#Incoming messages.
class incoming_message(models.Model):	
	#id is an AutoField in Django
	source_ip = models.GenericIPAddressField(max_length=45, validators=[validate_ipv46_address, MaxLengthValidator(45)])
	message_type = models.CharField(max_length=15, 
	                                choices=((u'Report', u'Report'),
	                                         (u'Result', u'Result'),
	                                         (u'Acknowledgement', u'Acknowledgement'),
	                                         (u'Request', u'Request'),
	                                         (u'Query', u'Query'),    
	                                        ),
	                                validators=[RegexValidator("^(Report|Result|Acknowledgement|Reqest|Query)$")]
	                                )
	created = models.DateTimeField()
	response_id = models.IntegerField(blank=True, null=True)
	xml = models.TextField(validators=[validators.RidMessageValidator])
	json = models.TextField(blank=True, null=True)
	
	def __unicode__(self):
		return str(self.id)

#Outgoing messages
class outgoing_message(models.Model):
	#id is an AutoField in Django
	ip_destination = models.CharField(max_length=50)
	created = models.TimeField(auto_now=True)
	xml = models.TextField(validators=[validators.RidMessageValidator])
	incoming_message_id = models.IntegerField()
	status = models.CharField(max_length=10, 
	                          choices=((u'pending',u'Pending'),
	                                   (u'sent',u'Sent'),
	                                   )
	                          )
	sent_time = models.TimeField(null=True)
	def __unicode__(self):
		return str(self.id)

#User profile. Each user can have one of three roles:
# - RID User; Allowed to login via GUI
# - RID Peer; Allowed to use the host:4590 interface for RID messages
# - RID Backend; Allowed to make API calls
#These roles are not exclusive of each other.
class user_profile(models.Model):
	user = models.OneToOneField(User)
	rid_user = models.BooleanField()
	rid_peer = models.BooleanField()
	rid_backend = models.BooleanField()

#This code enables the user profile, which right now consists
#of permissions. 
def create_user_profile(sender, instance, created, **kwargs):
	if created:
		profile = user_profile.objects.create(user=instance)
		profile.save()

post_save.connect(create_user_profile, sender=User)

#The certificate store.
class certificate(models.Model):
	#id is an AutoField in Django
	title = models.CharField(max_length=64)
	description = models.TextField(blank=True)
	subject = models.CharField(max_length=255, unique=True, editable=False, default='Unassigned')
	issuer = models.CharField(max_length=255, editable=False, default='Unassigned')
	pem_certificate = models.TextField(validators=[validators.CertificateValidator])
	created = models.TimeField(auto_now=True)
	
	def __unicode__(self):
		return self.title
	
	def clean(self):
		from django.core.exceptions import ValidationError
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.pem_certificate)
		x509subject = x509.get_subject()
		self.subject = str(x509subject)[18:-2]
		x509issuer = x509.get_issuer()
		self.issuer = str(x509issuer)[18:-2]

#Exports all of the certificates in the database to the client_certs/cacerts.crt file
def do_export_certs(sender, **kwargs):
	export_location = '/var/www/RID_Agent/RID_Agent/client_certs/cacerts.crt'
	#Open the export locatoin for clobbering
	export_file = open(export_location, 'w')
	all_certs = certificate.objects.all()
	for cert in all_certs:
		export_file.write(cert.pem_certificate + '\r\n')
	export_file.close()
	return

post_save.connect(do_export_certs, sender=certificate)
post_delete.connect(do_export_certs, sender=certificate)
