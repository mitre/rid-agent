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

from django.forms.util import ErrorList
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponse, Http404, HttpResponseNotAllowed, HttpResponseRedirect, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from datetime import datetime
import subprocess, OpenSSL
from decorators import access_required, access_required_or, login_required_no_redirect
import handlers, logging, settings
from lxml import etree
import httplib
import hashlib
import base64

from RID_Agent.models import incoming_message, outgoing_message, certificate
import RID_Agent.forms as forms

#The list of message types supported by this implementation
supported_rid_message_types = frozenset(['Acknowledgement','Report','Query'])
rid_message_types = frozenset(['Acknowledgement', 'Report', 'Query', 'Result', 'Request'])

#This is the login page. 
def login(request):
	logger = logging.getLogger('rid_agent.views.login')
	client_ip = handlers.GetRemoteIp(request)
	#If this is a GET request, render the login page and preserve any redirect info
	if request.method == 'GET':
		#Either redirect the user to the page they were trying to access,
		#or the default URL.
		if(request.GET is not None and 'next' in request.GET):
			next = request.GET['next']
		else:
			next = settings.LOGIN_REDIRECT_URL
		form = forms.LoginForm( initial={'next': next} )
		logger.info('Login page accessed from %s with next=%s', client_ip, next)
		return render_to_response('auth/login.html', {'form': form}, context_instance=RequestContext(request))
	
	#This is a POST request, meaning a login attempt.
        if request.method == 'POST':
		form = forms.LoginForm(request.POST)
		if not form.is_valid():#If the form isn't valid, render the login form again
			logger.debug('Login form invalid from %s', client_ip)
			return render_to_response('auth/login.html', 
						  {'form': form}, 
						   context_instance=RequestContext(request))
		
                username = request.POST['username']
                password = request.POST['password']
		redirect_url = request.POST['next']
                user = auth.authenticate(username=username, password=password)#attempt to auth the user
		logger.info('Login attempt for %s from %s.', username, client_ip)
                if user is not None and user.is_active: # Correct password, and the user is marked "active"
                        auth.login(request, user) # Log in the user
			logger.info('Login successful for %s from %s. Redirecting to %s', username, client_ip, redirect_url)
			return HttpResponseRedirect(redirect_url)#Success, redirect to the 'next' page
		logger.info('Login failed for %s from %s', username, client_ip)
		form._errors['username'] = ErrorList(['Login Failed'])
        	return render_to_response('auth/login.html', {'form': form}, context_instance=RequestContext(request))
	#Shouldn't get here, but just in case render the default login page
	logger.warning('Rendering a page that logically shouldn\'t be rendered. Request came from %s.', client_ip)
	return render_to_response('auth/login.html', {'form': forms.LoginForm}, context_instance=RequestContext(request))

#This is the logout page.
def logout(request):
	logger = logging.getLogger('rid_agent.views.logout')
	client_ip = handlers.GetRemoteIp(request)
	logger.info('User %s has logged out from %s', request.user.username, client_ip)
	auth.logout(request)
	return render_to_response('core/message.html', {
				  'title':'Logged out', 'message': 'Logout successful.'}, 
				  context_instance=RequestContext(request))

#This is the RID interface. In a production setting, this view should only be hit by
#RID Peers exchanging RID messages. The logging in here is more verbose because it is likely
#that debugging will be done after the fact
@csrf_exempt
def rid(request):
	client_ip = handlers.GetRemoteIp(request)
	logger = logging.getLogger('rid_agent.views.rid')
	logger.debug('Entering views.rid, request from %s; User not auth yet.', client_ip)
	
	#At this point, Apache should have authenticated the user using the SSLVerifyClient directive.
	#Now the app needs to read the client DN and use that to perform application authorization.
	if 'SSL_CLIENT_S_DN' not in request.META:
		logger.warn('Client Subject DN is not in the HTTP Headers; Returning Http 500 error')
		logger.info('Did you remember to add \'SSLOptions StdEnvVars\' to your SSL configuration file?') 
		return HttpResponse(status=500)#500 - Internal Server Error; The Client DN. This is more than likely a server error
	
	if 'SSL_CLIENT_S_DN_CN' not in request.META:
 		logger.warn('Client Subject CN is not in the HTTP Headers; Returning Http 500 error')
		logger.info('Did you remember to add \'SSLOptions StdEnvVars\' to your SSL configuration file?')
		return HttpResponse(status=500)#500 - Internal server error; The Client CN. This is more than likely a server error
	
	#The "username" is the CN of the SSL cert plus an underscore plus the MD5 of the 
	#DN. The "Password" is always 'Password123'. This method will create the user and
	#Set the appropriate role if the user does not already exist
	client_dn = request.META['SSL_CLIENT_S_DN']
	logger.debug('Got a DN of %s from %s', client_dn, client_ip)
	client_cn = request.META['SSL_CLIENT_S_DN_CN']
	logger.debug('Got a CN of %s from %s', client_cn, client_ip)
	username = client_cn
	username = username[:30]#TODO: This is not the best 'algorithm', and needs to be changed for a production system
	#			#The database table should be updated to allow long CNs (CNs over 30 chars), but that's
	#			#a bigger change than this
	logger.debug('Username is %s from %s', username, client_ip)
	password = 'Password123'
	
	user = auth.authenticate(username=username, password=password)#attempt to authenticate the user
	logger.info('Login attempt for %s from %s', username, client_ip)
	if user is None:# The user doesn't exist, need to create the user and associated profile with the appropriate permissions.
		user = User.objects.create_user(username, 'no@example.com', password)
		user.save()#Create the user, which also creates the user profile.
		user = auth.authenticate(username=username, password=password)#This shouldn't fail.
		if user is None or not user.is_active: #This _really_ shouldn't fail
			logger.error('The user (%s) that was just created from (%s) could not be logged in', username, client_ip)
			return HttpResponse(status=500)#500 - Internal Server Error
		#Modify the profile so that the user has the appropriate role
		profile = user.get_profile()
		profile.rid_peer = True
		profile.save()
	#After this point, any non-existing users should be authenticated
	auth.login(request, user)
	
	#Now we can check permissions
	user_profile = request.user.get_profile()
	allowed = getattr(user_profile, 'rid_peer')
	if not allowed:
		logger.info('The user %s from %s does not have the rid_peer permission; returning 403 forbidden', request.user.username, client_ip)
		return HttpResponse(status=403)#403 - Forbidden
	#Uncomment to log the headers for debugging purposes.
	#This is commented out because it is verbose
	#for header in request.META:
	#	logger.debug('%s: %s', header, request.META[header])
	
	#These IF statements implement the logical checks for HTTP headers.
	#The order is important per the wording in RFC 6546 section 3
	#The 'Request-URI' requirement is filled by urls.py	
	if request.method == 'GET' or request.method == 'HEAD':
		logger.info('%s request method was %s. Responded with 204 No Content', 
			    client_ip, request.method)
		return HttpResponse(status=204)#204 - No Content
	
	if request.method != 'POST':
		logger.info('%s request method was %s. Responded with 405 Not Allowed',
			    client_ip, request.method)
		return HttpResponseNotAllowed(['POST'])#405 - Not allowed, with allowed methods supplied
	
	if request.META['CONTENT_TYPE'] != 'text/xml': 
		logger.info('%s request content type was %s, not text/xml. Responded with 415 Unsupported Media Type',
			    client_ip, request.META['CONTENT_TYPE'])
		return HttpResponse(status=415)#415 - Unsupported Media Type
	
	#At this point, header and authentication preconditions are have been met.
	#We must now parse the POST data. It should be a valid RID/IODEF XML blob. At this layer
	#We simply check to see if it's schema-valid and push it into a message store.
	
	#TODO: Check encoding type
	#TODO: Use validators.RidMessageValidator, rather than this code
	xml_byte_string = request.body
	xml_string = xml_byte_string.decode("utf-8")
	#TODO: This should probably be done by the webserver
	xml_size = len(xml_string)
	if xml_size > settings.MAX_RID_MESSAGE_SIZE:
		logger.info('%s request had a size of %s, larger than the mas size of %s.' + 
			    ' Responding with 413 Request Entity Too Large',
			    client_ip, xml_size, settings.MAX_RID_MESSAGE_SIZE)
		return HttpResponse(status=413)#413 - Request Entity Too Large
	
	#Determine if the XML is well formed. If not, respond w/ HTTP 400
	parsed, xml_doc = handlers.StringToXml(xml_string)
	if not parsed:
		logger.info('User %s sent XML document from %s. Parse error: %s ',
			    request.user.username, client_ip, xml_doc)
		return SimpleTemplateResponse('core/message.html',
					      {'title': 'XML Parse Error',
					       'message': str(xml_doc)},
					       status=400)#400 - Bad Request
	
	#Determine whether or not the XML is schema valid.
	#If it's not, responde with an HTTP 400.
	schema_valid, message = handlers.IsValidRid(xml_doc)
	if not schema_valid:
		logger.info('User %s sent XML document from %s. Schema validation error: %s ', 
			    request.user.username, client_ip, xml_doc)
		return SimpleTemplateResponse('core/message.html', 
                                              {'title': 'XML Parse or Schema Validation Error', 
                                               'message': str(message)}, 
                                              status=400)#400 - Bad Request
	
	#At this point, the XML document is well formed and is schema valid
	logger.debug('User %s sent valid XML document from %s', request.user.username, client_ip)
	type = handlers.GetRidMessageType(xml_doc)
	
	#Do some checking on the RID message type.
	if type not in rid_message_types:
		logger.info('%s RID Message type was %s. Responding with HTTP 400 Bad Request',
			    client_ip, type)
		return HttpResponse("The supplied RID type was not valid", status=400)#400 - Bad Request
	
	if type not in supported_rid_message_types:
		logger.info('%s RID Message type was %s. Responding with HTTP 501 Not Implemented',
			    client_ip, type)
		return HttpResponse("The supplied RID type is not currently supported.", status=501)#501 - Not Implemented
	
	#Save the message and return HTTP 202
	logger.info('%s RID message, attempting to save', client_ip)
	success, return_code = handlers.SaveIncomingMessage(client_ip, type, xml_string)
	logger.info('%s RID message save status=%s; Return code (ID?) %s', client_ip, success, return_code)
	
	if type == 'Query':
		return HttpResponse(status=202)
	return HttpResponse(status=200)

@login_required
@access_required('rid_user')
def tools_build_incoming_api_query(request):
	logger = logging.getLogger('rid_agent.views.tools_build_incoming_api_query')
	client_ip = handlers.GetRemoteIp(request)
	
	#Default case for vars
	query_string = ''
	form = forms.PullIncomingMessageForm
	
	if len(request.GET) > 0:#There are any supplied get params
		form = forms.PullIncomingMessageForm(request.GET)
		if form.is_valid():
			for k, v in form.cleaned_data.items():
				query_string += '&%s=%s' % (k, v)
	if len(query_string) > 0:
		query_string = '?' + query_string[1:]
	
	return render_to_response('tools/build_incoming_api_query.html',
				  {'form': form,
				   'title': 'Incoming Message Query Builder',
				   'query_string': query_string,
				   'url': '/api/1.0/pull_incoming_messages/'},
				  context_instance=RequestContext(request))


@login_required
@access_required('rid_user')
def tools_build_outgoing_api_push(request):
	logger = logging.getLogger('rid_agent.views.tools_build_outgoing_api_push')
	client_ip = handlers.GetRemoteIp(request)
	
	post_data = ''
	form = forms.PushOutgoingMessageForm
	
	if len(request.POST) > 0:
		form = forms.PushOutgoingMessageForm(request.POST)
		if form.is_valid():#Build the request
			post_data = '<api_request '
			post_data += 'destination="%s"' % form.cleaned_data['ip_destination']
			if 'incoming_message_id' in form.cleaned_data:
				post_data += ' incoming_message_id="%s"' % form.cleaned_data['incoming_message_id']
			post_data += '>'
			post_data += form.cleaned_data['xml']
			post_data += '</api_request>'
	
	return render_to_response('tools/build_outgoing_api_push.html',
				  {'form': form,
				   'post_data': post_data},
				 context_instance=RequestContext(request))
@login_required
@access_required('rid_user')
def tools_check_cert_chains(request):
	logger = logging.getLogger('rid_agent.views.tools_check_cert_chains')
	client_ip = handlers.GetRemoteIp(request)

	#Load the DB certs into memory for quick access
	all_certs = certificate.objects.all().values()
	cert_dict = {}
	for cert in all_certs:
		cert_dict[cert['subject']] = cert
	
	
	results_dict = {}
	for cert_subj in cert_dict:
		cert = cert_dict[cert_subj]
		cert['issuer_in_db'] = cert['issuer'] in cert_dict
		try:
			x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert['pem_certificate'])
			if x509.has_expired():
				cert['expired'] = 'Yes'
			else:
				cert['expired'] = 'No'
		except:
			cert['expired'] = 'Unknown Error'
		results_dict[cert_subj] = cert
	
	return render_to_response('tools/check_cert_chains.html',
				  {'chain_data': results_dict},
				  context_instance=RequestContext(request))


@login_required
@access_required('rid_user')
def manage(request, action=''):
	if (action == ''):
		return render_to_response('manage/index.html', context_instance=RequestContext(request))
	elif (action == 'web_api_integration'):
		return render_to_response('manage/web_api_integration.html',
					  {'incoming_model': models.incoming_message},
					  context_instance=RequestContext(request))
	else:
		raise Http404

#TODO: Consider deprecating this. The word doc is sufficient documentation
@login_required
@access_required('rid_user')
def docs(request, action=''):
	if (action == ''):
		template = 'index.html'
	elif (action == 'architecture'):
		template = 'architecture.html'
	elif (action == 'references'):
		template = 'references.html'
	elif (action == 'web_api_integration'):
		template = 'web_api_integration.html'
	else:
		raise Http404
	return render_to_response('docs/' + template, context_instance=RequestContext(request))

@login_required
@access_required('rid_user')
def logs(request):
	if len(request.GET) == 0:#There is not any form data
		return render_to_response('logs/index.html',
					  {'form': forms.LogViewForm,
					   'logs': handlers.GetLogs()},
					   context_instance=RequestContext(request))
	#There's form data
	form = forms.LogViewForm(request.GET)
	if not form.is_valid():#If the form is not valid, just spit it back at the user
		return render_to_response('logs/index.html',
					  {'form': form,
					   'logs': handlers.GetLogs()},#TODO: Do something a little more intelligent
								       #Like echo the previous request
					  context_instance=RequestContext(request))
	
	#The form is valid
	
	return render_to_response('logs/index.html',
				  {'form': form,
				   'logs': handlers.GetLogs(form)},
				   context_instance=RequestContext(request))

@login_required
@access_required('rid_user')
def tools_index(request):
	logger = logging.getLogger('rid_agent.views.tools.index')
	client_ip = handlers.GetRemoteIp(request)
	logger.debug('Entering tools/index; request from %s', client_ip)
	return render_to_response('tools/index.html', context_instance=RequestContext(request))

@login_required
@access_required('rid_user')
def tools_send_rid_message(request):
	logger = logging.getLogger('rid_agent.views.tools_send_rid_message')
	client_ip = handlers.GetRemoteIp(request)
	if request.method != 'POST':
		logger.info('User %s from %s rendering tools/send_rid_message', request.user.username, client_ip)
		return render_to_response('tools/send_rid_message.html',
				          {'form': forms.SendRidMessageForm()},
					  context_instance=RequestContext(request))
	#Method is POST
	form = forms.SendRidMessageForm(request.POST)
	logger.debug('User %s from %s Attempting to validate form', request.user.username, client_ip)
	try:
		if not form.is_valid():
			logger.debug('Form not valid, raising error.')
			raise Exception(None, None)
		
		xml_string = request.POST['rid_message']
		parsed, xml_doc = handlers.StringToXml(xml_string)
		if not parsed:
			logger.debug('RID Message not valid XML, raising error.')
			raise Exception('rid_message', str(xml_doc))
		
		schema_valid, message = handlers.IsValidRid(xml_doc)
		if not schema_valid:
			logger.debug('RID Message not Schema valid, raising error.')
			raise Exception('rid_message', str(message))
	except Exception as (field, error):
		if field is not None:
			logger.debug('Error was: %s; %s. Rendering form', field, error)
			form._errors[field] = ErrorList([error])
		return render_to_response('tools/send_rid_message.html',
					  {'form': form},
					  context_instance=RequestContext(request))
	#At this point, the form is valid
	ip_dest = request.POST['ip_destination']
	use_https = request.POST['use_https']
	logger.debug('Sending RID message to %s', ip_dest)
	#Success can be one of three strings: 'True', 'False', or 'Error'
	success, response = handlers.SendRidMessageToPeer(ip_dest, xml_string, use_https)
	msg_dict = {'success': success, 'message': response}
	if success == 'True' or success == 'False':
		msg_dict['message_body'] = response.read()
		
	logger.debug('Returning HTTP Response to submit_rid_message')
	return render_to_response('tools/submit_rid_message.html',
				  msg_dict,
				  context_instance=RequestContext(request))


###############################
##  BEGIN API 1.0 FUNCTIONS   #
###############################

def api_10_login(request):
	#At some point 'Authorization' gets
	#re-written to 'HTTP_AUTHORIZATION'
	AUTH_HEADER = 'HTTP_AUTHORIZATION'
	logger = logging.getLogger('rid_agent.views.api_10_login')
	
	client_ip = handlers.GetRemoteIp(request)
	logger.info('API 1.0 login request from %s.', client_ip)
	
	if request.user.is_authenticated():#User already logged in
		values_dict = {'type': 'success',
			       'message': 'Already logged in!',
			      }
		logger.info('User %s from %s was already logged in.', request.user.username, client_ip)
		return handlers.get_api_10_response(values_dict)
	
	if AUTH_HEADER not in request.META:#User is not logged in, no credentials to verify
		values_dict = {'type': 'error',
				'message': 'No authentication parameters provided in the %s header.' % AUTH_HEADER,
			       'status_code': '401'
			      }
		logger.info('Request from %s. No authentication parameters provided in the %s header.', 
			    AUTH_HEADER, client_ip)
		logger.debug('Request from %s header list.', client_ip)
		for header in request.META:
			logger.debug('\t%s=%s', header, request.META[header])
		logger.debug('Request from %s. End header list.', client_ip)
		resp = handlers.get_api_10_response(values_dict)
		resp['WWW-Authenticate'] = 'Basic realm="Please provide credentials"'
		return resp
	
	auth_info = request.META[AUTH_HEADER].split()
	if len(auth_info) != 2:#User is not logged in, no credentials to verify
		values_dict = {'type': 'error',
			       'message': 'There was an error with the authentication parameters'}
		logger.info('Request from %s. There was an error with the %s header. Header value: %s', 
			     client_ip, AUTH_HEADER, request.META[AUTH_HEADER])
		return handlers.get_api_10_response(values_dict)
	
	if auth_info[0].lower() != 'basic':#User is not logged in, no credentials to verify
		values_dict = {'type': 'error',
			       'message': 'HTTP Auth Type was not basic. Only basic auth is currently supported'}
		logger.info('Request from %s. HTTP Auth Type was not basic. Auth type was %s. Only basic auth is currently supported',
			    client_ip, auth[0])
		return handlers.get_api_10_response(values_dict)
	#Attempt to log them in
	uname, passwd = base64.b64decode(auth_info[1]).split(':')
	logger.info('Request from %s. Attempting login as %s.', client_ip, uname)
	user = auth.authenticate(username=uname, password=passwd)
	
	if user is None:#User could not log in
		values_dict = {'type': 'error',
			       'message': 'The supplied credentials were invalid'}
		logger.info('Request from %s for user %s. User was None', client_ip, uname)
		return handlers.get_api_10_response(values_dict)
	
	if not user.is_active:#User is not active
		values_dict = {'type': 'error',
			       'message': 'The user is not active.'}
		logger.info('Request from %s for user %s. User is not active.', client_ip, uname)
		return handlers.get_api_10_response(values_dict)
	
	auth.login(request, user) # Log in the user
	
	#Authentication was successful!
	values_dict = {'type': 'success',
		       'message': 'Login successful!'}
	logger.info('User %s from %s. Login successful.', uname, client_ip)
	return handlers.get_api_10_response(values_dict)

@login_required_no_redirect()
@access_required('rid_backend')
def api_10_logout(request):
	logger = logging.getLogger('rid_agent.views.api_10_logout')
	client_ip = handlers.GetRemoteIp(request)
	logger.info('User %s from %s. API 1.0 logged out.', request.user.username, client_ip)
	auth.logout(request)
	values_dict = {'type': 'success',
		       'message': 'Logout successful!'}
	return handlers.get_api_10_response(values_dict)
	
@login_required_no_redirect()
@access_required('rid_backend')
def api_10_pull_incoming_messages(request):
	logger = logging.getLogger('rid_agent.views.api_10_pull_incoming_messages')
	client_ip = handlers.GetRemoteIp(request)
	logger.info('User %s from %s. Entering API pull incoming messages', request.user.username, client_ip)
	allowed_get_params = frozenset(['id','source_ip','message_type','created',
					'created__gt', 'xml', 'response_id',
					'limit'])
	
	if len(request.GET) == 0:#No get parameters were supplied
		values_dict = {'type': 'error',
			       'message': 'There were not any query parameters'}
		logger.info('User %s from %s. No GET parameters were supplied', request.user.username, client_ip)
		return handlers.get_api_10_response(values_dict)
	
	form = forms.PullIncomingMessageForm(request.GET)
	if not form.is_valid():#Error
		errors = '<error_list>'
		for field in form:
			if field.errors:
				errors += '<error>'
				errors += str(field.name) + ': ' + str(field.errors[0])
				errors += '</error>'
		errors += '</error_list>'
		values_dict = {'type': 'error',
			       'message': 'There was an error processing the query parameters',
			       'content': errors} 
		logger.info('User %s from %s. Get parameters not valid. %s', request.user.username, client_ip, errors)
		return handlers.get_api_10_response(values_dict)
	
	form_dict = form.cleaned_data
	
	#Everything looks good (I think)
	#Do the query!
	
	if len(form_dict) == 0:
		values_dict = {'type': 'error',
				'message': 'There were not any query parameters'}
		logger.info('User %s from %s. There were not any query parameters', request.user.username, client_ip)
		return handlers.get_api_10_response(values_dict)
	
	limit = None
	if 'limit' in form_dict:
		limit = form_dict['limit']
		del form_dict['limit']
	
	if limit is not None:
		messages = incoming_message.objects.order_by('created').filter(**form_dict)[:limit]
	else:
		messages = incoming_message.objects.order_by('created').filter(**form_dict)
	
	values_dict = {'type': 'success',
		       'message': 'The query was successful',
		       'content': handlers.IncomingMessagesToXml(messages)}
	
	logger.info('User %s from %s. Query resulted in %s results', request.user.username, client_ip, len(messages))
	return handlers.get_api_10_response(values_dict)

@csrf_exempt
@login_required_no_redirect()
@access_required('rid_backend')
#TODO: This code just puts a message in the database, but there is 
#      not any code to send messages from the database.
#      this should probably be hooked up to the 'Send a RID Message' handler.
def api_10_push_outgoing_message(request):
	logger = logging.getLogger('rid_agent.views.api_10_push_outgoing_message')
	client_ip = handlers.GetRemoteIp(request)
	
	if len(request.POST) == 0:
		values_dict = {'type': 'error',
			       'message': 'There was not any POST data.'}
		return handlers.get_api_10_response(values_dict)
	
	xml_string = request.POST
	
	parsed, xml_doc = handlers.StringToXml(xml_string)
	if not parsed:
		values_dict = {'type': 'error',
			       'message': 'The XML was not valid: %s' % xml_doc}
		return handlers.get_api_10_response(values_dict)
	
	dest_ip = xml_doc.attrib['destination']
	incoming_message_id = None
	if 'incoming_message_id' in xml_doc.attrib:
		incoming_message_id = xml_doc.attrib['incoming_message_id']
	rid_xml_doc = xml_doc.find('{urn:ietf:params:xml:ns:iodef-rid-2.0}:RIDPolicy')
	
	valid, message = handlers.IsValidRid(rid_xml_doc)
	if not valid:
		values_dict = {'type': 'error',
			       'message': 'RID Message was not valid: %s' % message}
		return handlers.get_api_10_response(values_dict)
	
	rid_xml_string = etree.tostring(rid_xml_doc)
	handlers.SaveOutgoingMessage(dest_ip, incoming_message_id, rid_xml_string)
	
	values_dict = {'type': 'success',
		       'message': 'The message was saved successfully.',
		       'content': rid_xml_string}
	
	return handlers.get_api_10_response(values_dict)

###############################
##   END API 1.0 FUNCTIONS    #
###############################
