[comment]: # "Auto-generated SOAR connector documentation"
# Videotron CMDB

Publisher: Splunk Community  
Connector Version: 1\.0\.1  
Product Vendor: Videotron  
Product Name: CMDB  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app integrates with the Videotron CMDB tool to perform lookups

[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
The app uses HTTP/ HTTPS protocol for communicating with the Videotron CMDB server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a CMDB asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Server URL \(e\.g\. https\://10\.10\.10\.10\:38080\)
**verify\_ssl** |  optional  | boolean | Verify Server Certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[query device](#action-query-device) - Lookup device details  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'query device'
Lookup device details

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** |  required  | Hostname to query | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.data\.\*\.CI\_Child\.\*\.ClassId | string | 
action\_result\.data\.\*\.CI\_Child\.\*\.HasImpact | string | 
action\_result\.data\.\*\.CI\_Child\.\*\.HasImpactID | string | 
action\_result\.data\.\*\.CI\_Child\.\*\.Name | string | 
action\_result\.data\.\*\.CI\_Child\.\*\.ReconciliationIdentity | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Environment | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Environment\_ID | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Impact | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Impact\_ID | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Name | string |  `host name` 
action\_result\.data\.\*\.CI\_Info\.\*\.ReconciliationIdentity | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Status | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Status\_ID | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Supported | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Supported\_ID | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Urgency | string | 
action\_result\.data\.\*\.CI\_Info\.\*\.Urgency\_ID | string | 
action\_result\.data\.\*\.CI\_SupportGroup\.\*\.PeopleGroup\_Form\_Entry\_ID | string | 
action\_result\.data\.\*\.CI\_SupportGroup\.\*\.Person\_Role | string | 
action\_result\.data\.\*\.CI\_SupportGroup\.\*\.Person\_Role\_ID | string | 
action\_result\.data\.\*\.CI\_SupportGroup\.\*\.Support\_Group\_Name | string | 
action\_result\.summary\.managed\_by | string | 
action\_result\.summary\.status | string | 
action\_result\.summary\.used\_by | string | 
action\_result\.summary\.supported\_by | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 