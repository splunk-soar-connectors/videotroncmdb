#!/usr/bin/python
# -*- coding: utf-8 -*-

# File: videotroncmdb_connector.py
# Copyright (c) 2020-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class VideotronCmdbConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(VideotronCmdbConnector, self).__init__()

        self._state = None

        self._base_url = None
        self._verify_ssl = None
        self._username = None
        self._password = None
        self._auth_token = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except ValueError as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Unable to parse JSON response. Error: {e}"
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Get auth_token from response if not already available
        if not self._auth_token:
            if r.headers.get('Authentication-Token', None):
                self._auth_token = r.headers['Authentication-Token']
                return RetVal(phantom.APP_SUCCESS, None)
            else:
                return RetVal(action_result.set_status(phantom.APP_SUCCESS, 
                'Unable to retrieve Authentication-Token from returned headers.'), None)

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", headers=None, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        if self._auth_token:
            if headers:
                headers.update({
                    'Authentication-Token': self._auth_token
                })
            else:
                headers = {
                    'Authentication-Token': self._auth_token
                }

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"),
                resp_json
            )

        # Create a URL to connect to
        url = f'{self._base_url}/{endpoint}'

        try:
            r = request_func(
                url,
                verify=self._verify_ssl,
                headers=headers,
                **kwargs
            )
        except requests.exceptions.RequestException as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Error Connecting to server. Details: {e}"
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _login(self, action_result):
        body = {
            'username': self._username,
            'password': self._password
        }
        ret_val, _ = self._make_rest_call('baocdp/rest/login', action_result, method='post', json=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _logout(self):
        if not self._auth_token:
            return

        headers = {
            'Authentication-Token': self._auth_token
        }
        r = requests.post(
            f'{self._base_url}/baocdp/rest/logout',
            verify=self._verify_ssl,
            headers=headers,
            timeout=60
        )
        try:
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.debug_print(f'Unable to logout correctly: {e}')

        return

    def _parse_json_object(self, raw_object):
        """ Parse raw_object if it is a string containing a JSON object, otherwise return raw_object, as is.
        Note: This is meant to future proof the app if the API starts to return a JSON object instead of a string containing JSON.
        """
        try:
            return json.loads(raw_object)
        except ValueError:
            return raw_object

    def _to_dict(self, list_of_dicts, key='name', value='value'):
        """ Translate list of dicts to a single dict. """
        translated_dict = {}
        for d in list_of_dicts:
            if key in d and value in d:
                translated_dict[d[key]] = self._parse_json_object(d[value])
            else:
                self.debug_print(f'Unable to find {key} or {value} in returned dict: {d}')

        return translated_dict

    def _from_dict(self, d, key='name', value='value'):
        """ Translate dict to list of dicts """
        list_of_dicts = []
        for k, v in d.items():
            list_of_dicts.append({key: k, value: v})

        return list_of_dicts

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Attempting to login via API")
        # make rest call
        ret_val = self._login(action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_query_device(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(f'In action handler for: {self.get_action_identifier()}')

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._login(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Access action parameters passed in the 'param' dictionary
        hostname = param['hostname']

        data = {
            'inputParameters': self._from_dict({
                'CIName': hostname,
                'Include Child': True,
                'Include Parent': True,
                'Include SupportInfo': True,
                'Include Outage': True
            })
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            'baocdp/rest/process/%3AVID_ITSM_API%3ACMDB%3AGet%20CI%20Information/execute?mode=sync',
            action_result,
            method='post',
            json=data
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        response = self._to_dict(response)
        action_result.add_data(response.get('Data', response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = response.get('Status')

        if isinstance(response.get('Data'), dict):
            for i, support_group in enumerate(response.get('Data', {}).get('CI_SupportGroup', [])):
                if isinstance(support_group, dict):
                    person_role = support_group.get('Person_Role', f'Missing_Role_{i}').replace(' ', '_').lower()
                    sg_name = support_group.get('Support_Group_Name', f'Missing_Name_{i}')
                    summary[person_role] = sg_name

        if response.get('Message'):
            return action_result.set_status(phantom.APP_SUCCESS, response['Message'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, 'Success')

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'query_device':
            ret_val = self._handle_query_device(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        config = self.get_config()

        self._base_url = config['base_url'].rstrip('/')
        self._verify_ssl = config.get('verify_ssl', False)
        self._username = config['username']
        self._password = config['password']

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        self._logout()

        return phantom.APP_SUCCESS


def main():

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = VideotronCmdbConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=60)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=60)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VideotronCmdbConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == '__main__':
    main()
