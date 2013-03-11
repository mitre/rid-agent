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

from django.conf import settings
from django import forms
from django.forms.widgets import RadioSelect, HiddenInput, CheckboxInput, MultiWidget
import models
import datetime

#Form for sending a RID message
class SendRidMessageForm(forms.Form):
	ip_destination = forms.CharField(label='IP Destination', 
					 max_length=100,
					 required=True)
	rid_message = forms.CharField(label='RID Message', 
                      widget=forms.Textarea(attrs={'cols': '50', 'rows': '10'}), required=True)
	use_https = forms.BooleanField(label='Use HTTPS', required=False, initial=True)

class LogViewForm(forms.Form):
	debug = forms.BooleanField(required=False, initial=True)
	info = forms.BooleanField(required=False, initial=True)
	warning = forms.BooleanField(required=False, initial=True)
	error = forms.BooleanField(required=False, initial=True)
	critical = forms.BooleanField(required=False, initial=True)
	exception = forms.BooleanField(required=False, initial=True)

class LoginForm(forms.Form):
	username = forms.CharField()
	password = forms.CharField(widget=forms.PasswordInput)
	next = forms.CharField(widget=forms.HiddenInput)


class PushOutgoingMessageForm(forms.ModelForm):
	incoming_message_id = forms.CharField(required=False, initial='')
	
	class Meta:
		model = models.outgoing_message
		fields = ('ip_destination', 'incoming_message_id','xml')
	
	def clean(self):
		cleaned_data = super(PushOutgoingMessageForm, self).clean()
		return_values = {}
		for k in cleaned_data:
			v = cleaned_data[k]
			if v is not None and v != '':
				return_values[k] = v
		return return_values

class PullIncomingMessageForm(forms.ModelForm):
	id = forms.CharField(required=False, initial='')
	source_ip = forms.CharField(required=False, initial='')
	message_type = forms.ChoiceField(choices=[('','--------'),
						  ('Report','Report'),
						  ('Query', 'Query'),
						  ('Acknowledgement', 'Acknowledgement')],
					 required=False)
	created = forms.CharField(required=False, initial='')
	created__gt = forms.CharField(required=False, initial='')
	xml = forms.CharField(required=False, initial='')
	limit = forms.IntegerField(required=False, initial='')
	
	class Meta:
		model = models.incoming_message
		fields = ('id','source_ip','message_type','created','created__gt',
			  'xml','limit')
		exclude = ('json')

	#This method is overridden to remove blank and None values
	#from the cleaned data
	def clean(self):
		cleaned_data = super(PullIncomingMessageForm, self).clean()
		return_values = {}
		for k in cleaned_data:
			v = cleaned_data[k]
			if v is not None and v != '':
				return_values[k] = v
		
		try:
			if 'created__gt' in return_values:
				return_values['created__gt'] = \
					datetime.datetime.strptime(return_values['created__gt'], '%Y-%m-%d %H:%M:%S.%f')
		except:
			self._errors['created__gt'] = self.error_class(['Could not parse time. Required format: ' +
									'yyyy-mm-dd hh:mm:ss.ssssss'])
			del cleaned_data['created__gt']
		
		try:
			if 'created' in return_values:
				return_values['created'] = \
					datetime.datetime.strptime(return_values['created'], '%Y-%m-%d %H:%M:%S.%f')
		except:
			self._errors['created'] = self.error_class(['Could not parse time. Required format: ' + 
								     'yyyy-mm-dd hh:mm:ss.ssssss'])
			del cleaned_data['created']
			
		return return_values

