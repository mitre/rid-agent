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

import os
import sys
import django.core.handlers.wsgi
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "RID_Agent.settings")

my_path = '/var/www/RID_Agent'
if my_path not in sys.path:
	sys.path.append(my_path)

application = django.core.handlers.wsgi.WSGIHandler()
