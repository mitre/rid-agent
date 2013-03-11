
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

from functools import wraps
from django.shortcuts import render_to_response
from django.template import RequestContext
import handlers
from django.http import HttpResponse

#The default Django @login_required decorator is hardwired
#To return a 302 redirect, which is explicitly disallowed
#by the RID-IODEF spec
def login_required_no_redirect():
	def decorator(func):
		def inner_decorator(request, *args, **kwargs):
			if request.user.is_authenticated():
				return func(request, *args, **kwargs)
			else:
				values_dict = {'type': 'error',
					       'message': 'Authentication is required to view this resource.',
					       'status_code': '401'}
				return handlers.get_api_10_response(values_dict)
				#return HttpResponse('Authentication is required to access this resource.', status=401)
		return wraps(func)(inner_decorator)
	return decorator

#allows the function to execute if the user
#has any of the specified permissions
def access_required_or(permission_list):
	def decorator(func):
		def inner_decorator(request, *args, **kwargs):
			try:
				user_profile = request.user.get_profile()
			except:
				return render_to_response('core/message.html',
							  {'title': 'Authorization error',
							   'header': 'Authorization error',
							   'message': 'There is not a user profile associated with this user.'},
							  context_instance=RequestContext(request))
			allowed = False
			for permission in permission_list:
				try:
					allowed = allowed or getattr(user_profile, permission)
				except:
					allowed = allowed
					#Trap this error
			
			if allowed:
				return func(request, *args, **kwargs)
			else:
				return render_to_response('core/message.html',
							  {'title': 'Access Denied',
							  'header': 'Access Denied',
							  'message': 'Access has been denied to this page.' +
							  'Contact your system administrator for access.'},
							  context_instance=RequestContext(request))
		return wraps(func)(inner_decorator)
	return decorator

#Allows the function to execute ONLY if the user
#has the specified permission.
#A permission, in this case, is a boolean
#property in the user object.
def access_required(permission):
	def decorator(func):
		def inner_decorator(request, *args, **kwargs):
			try:
				user_profile = request.user.get_profile()
			except:
				return render_to_response('core/message.html', 
					   {'title': 'Authorization error',
					    'header': 'Authorization error',
					    'message': 'There is not a user profile associated with this user.'},
					   context_instance=RequestContext(request))
			try:
				allowed = getattr(user_profile, permission)
			except:
				return render_to_response('core/message.html',
						   {'title': 'Bad Permission Value',
						    'header': 'Bad Permission Value',
						    'message': 'The coder checked for a bad permission.'},
						    context_instance=RequestContext(request))
			if allowed:
				return func(request, *args, **kwargs)
			else:
				return render_to_response('core/message.html',
							  {'title': 'Access Denied',
							   'header': 'Access Denied',
							   'message': 'Access has been denied to this page.' + 
							    'Contact your system administrator for access.'},
							  context_instance=RequestContext(request))
		return wraps(func)(inner_decorator)
	return decorator
