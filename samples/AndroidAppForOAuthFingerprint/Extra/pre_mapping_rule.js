/*
* The function of this mapping rule is to validate the username and password supplied in the initial registration flow
* of the Mobile Application. This can be either done via local registry (ISAM linked) validation or an external callout.
*
* @author: Jared Page, Asha Shivalingaiah & Trevor Norvill
*/
importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.oauth20);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.ibm.security.access.user);
importPackage(Packages.com.tivoli.am.rba.extensions);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Headers);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
importClass(Packages.java.util.ArrayList);
importClass(Packages.java.util.HashMap);

trace("info", "entry", "============================ Inside Pre Mapping rule ============================");
/**
 * This mapping rule uses a user registry for verification of the username 
 * and password for the ROPC scenario.
 * 
 * This is an example of how you could verify the username and password with an
 * user registry before the access token is generated, therefore preventing
 * the scenario where access tokens are created for invalid users and stored in
 * the cache with no way to remove them till they expire.
 *
 * A prerequisite for using this example is configuring the username and 
 * password authentication mechanism.
 * 
 * This example is the default method for verifying the username and password.

 * To disable this example, change the "ropc_registry_validation" variable 
 * to "false".
 */

var fp_pin_ropc = true;
var trackingid = null;


/**
 * This mapping rule shows an example of the ROPC scenario using an external
 * service for verification of the username and password.
 * 
 * This is an example of how you could verify the username and password with an
 * external service before the access token is generated, therefore preventing
 * the scenario where access tokens are created for invalid users and stored in
 * the cache with no way to remove them till they expire.
 * 
 * To enable this demo, change the "ropc_http_demo" variable to "true" and the
 * "verificationServer" variable to your own user verification service.
 */
/*
 * Force sourcing the ROPC password validation config from ldap.conf. This should be set
 * to true if its known that the Username/Password mechanism in AAC is not configured.
 */
var force_ldap_conf = false;
var ropc_http_demo = false;
//Username Password Hashed local strorage
var local_username = "Mobile_APP";
                      

var trace_pipe = "|||";
var request_type = null;
var grant_type = null;
var username = null;
var password = null;
var temp_attr = null;
var auth_operation_type = null;
var isAuthenticated = false;

var SORRY = "Sorry - something went wrong.";
var DEBUG_INVALID_CREDENTIALS = "Invalid username/password. Authentication failed.";
var DEBUG_EMPTY_CREDENTIALS = "No username or password provided.";
var DEBUG_INVALID_REQUEST = "grant_type is not supported.";

var CLIENT_INVALID_CREDENTIALS = "You've provided the wrong credentials. Please try again.";
var CLIENT_INVALID_REQUEST = "The request failed. Please try again.";

/**
* This methods provides a lookup table for the developer oriented debug messages. 
* These messages will be returned to the client but shouldn't be displayed to the client.
*
* @method errorCodeToDebugMessageLookupTable
* @param {String} str - error_code - the error_code to be associated and text returned. 
* @return {String} str - error_text - The text associated with the supplied error_code. 
*/
function errorCodeToDebugMessageLookupTable(error_code) {
	var methodName = "errorCodeToDebugMessageLookupTable";
	trace("enter", methodName);

	var messageLookupTableSwitch = {
		"PreDI000": function() {
			return SORRY;
		},
		"PreDI001": function() {
			return DEBUG_INVALID_CREDENTIALS;
		},
		"PreDI002": function() {
			return DEBUG_EMPTY_CREDENTIALS;
		},
		"PreDI003": function() {
			return DEBUG_INVALID_REQUEST;
		},
		"PreDI004": function() {
			return DEBUG_INVALID_HEADER;
		}
	};

	trace("exit", methodName);
	return messageLookupTableSwitch[error_code]();
}

/**
* This methods provides a lookup table for the customer oriented error messages. 
* These messages will be returned to the client and are friendly - so can be directly displayed if needed.
*
* @method errorCodeToClientMessageLookupTable
* @param {String} str - error_code - the error_code to be associated and text returned. 
* @return {String} str - error_text - The text associated with the supplied error_code. 
*/
function errorCodeToClientMessageLookupTable(error_code) {
	var methodName = "errorCodeToClientMessageLookupTable";
	trace("enter", methodName);

	var messageLookupTableSwitch = {
		"PreCI000": function() {
			return SORRY;
		},
		"PreCI001": function() {
			return CLIENT_INVALID_CREDENTIALS;
		},
		"PreCI002": function() {
			return CLIENT_INVALID_REQUEST;
		}
	};

	trace("exit", methodName);
	return messageLookupTableSwitch[error_code]();
}

/**
*
* @method trace
* @param {String} str - type - the type of information to log.
* @param {String} str - methodName - the name of the function logging the information. 
* @param {String} str - message - the message to be logged. 
* @return {null or STSException} null
*/
function trace(type, methodName, message, second_message) {
	var enterTracePrepend = ">>>>>>>>>> enter:";
	var enterTraceAppend = " >>>>>>>>>>";
	var exitTracePrepend = "<<<<<<<<<< exit:";
	var exitTraceAppend = " <<<<<<<<<<";
	var errorTracePrepend = "========= error:";
	var warningTracePrepend = "========= warning:";
	var successTracePrepend = "========= success:";
	var infoTracePrepend = "========= info:";
	var infoTraceAppend = "=========";

	if (type == "enter") {
		IDMappingExtUtils.traceString( enterTracePrepend + " " + methodName + " " + enterTraceAppend);
	} else if (type == "exit") {
		IDMappingExtUtils.traceString( exitTracePrepend + " " + methodName + " " + exitTraceAppend);
	} else if (type == "error") {
		IDMappingExtUtils.traceString( errorTracePrepend + " " + methodName + " " + message + " " + infoTraceAppend);
		OAuthMappingExtUtils.throwSTSException( "pre_token_mapping_rule:"+methodName+"() " + trace_pipe + message + trace_pipe + second_message);
	} else if (type == "warning") {
		IDMappingExtUtils.traceString( warningTracePrepend + " " + methodName + " " + message + " " + infoTraceAppend);
	} else if (type == "success") {
		IDMappingExtUtils.traceString( successTracePrepend + " " + methodName + " " + message + " " + infoTraceAppend);
	} else if (type == "info") {
		IDMappingExtUtils.traceString( infoTracePrepend + " " + methodName + " " + message + " " + infoTraceAppend);
	}
}

/**
* Common function to remove given attribute set form the AAC response.
*
* @method addCustomResponseAttributes
* @param {Array} arr - attribute_array - the attributes to removed.
* @return {null or STSException} null
*/
function removeAttributes(attribute_array) {
	var methodName = "removeAttributes";
	trace("enter", methodName);

	for (var i = 0; i < attribute_array.length; i++) {
		trace("info", methodName, "Removing attribute: " + attribute_array[i]);
		stsuu.getContextAttributes().removeAttributeByNameAndType(attribute_array[i], "urn:ibm:names:ITFIM:oauth:response:attribute");
		stsuu.getContextAttributes().removeAttributeByNameAndType(attribute_array[i], "urn:ibm:names:ITFIM:oauth:response:metadata");
	}

	var context_attributes = stsuu.getAttributeContainer();
	for (var i = 0; i < context_attributes.length; i++) {
		trace("info", methodName, "Context attribute: " + context_attributes[i]);
	}
	trace("exit", methodName);
}

/**
*
* @method handleErrore
* @param {Object} obj - error_message - the error_message object
* @return {null or STSException} null
*/
function handleError(error_message) {
	var methodName = "handleError";
	trace("enter", methodName);

	var error_stacktrace = error_message.split(trace_pipe).length == 3 ? error_message.split(trace_pipe)[0] : "com.tivoli.am.fim.trustserver.sts.STSException: post_token_mapping_rule:1153:handleError()";
	var debug_error_code = error_message.split(trace_pipe).length == 3 ? error_message.split(trace_pipe)[1] : "PreDI000";
	var client_error_code = error_message.split(trace_pipe).length == 3 ? error_message.split(trace_pipe)[2] : "PreCI000";
	var error_debug_message = errorCodeToDebugMessageLookupTable(debug_error_code);
	var error_message_client = errorCodeToClientMessageLookupTable(client_error_code);

	stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("auth_ext_msg", "urn:ibm:names:ITFIM:oauth:response:attribute", error_message_client));
	stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("auth_ext_result", "urn:ibm:names:ITFIM:oauth:response:attribute", "false"));
	stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("auth_ext_success", "urn:ibm:names:ITFIM:oauth:response:attribute", "false"));
	stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("auth_ext_error_message", "urn:ibm:names:ITFIM:oauth:response:attribute", error_message_client));
	stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("auth_ext_error_debug_message", "urn:ibm:names:ITFIM:oauth:response:attribute", error_debug_message));
	stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("auth_ext_error_code", "urn:ibm:names:ITFIM:oauth:response:attribute", debug_error_code));
	stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("auth_ext_error_stacktrace", "urn:ibm:names:ITFIM:oauth:response:attribute", error_stacktrace));

	var attribute_array = ['access_token', 'expires_in', 'token_type', 'scope'];
	removeAttributes(attribute_array);

	OAuthMappingExtUtils.throwSTSException("pre_token_mapping_rule:"+methodName+"() " + trace_pipe + error_debug_message + trace_pipe + error_message_client);

	trace("exit", methodName);
}

// ========================================= ^^ HELPER FUNCTIONS ^^ ================================================

/**
* This method populates the global variables in this mapping rule with the variables from the 
* incoming request.
*
* @method setIncomingVariables
* @return {null or STSException} null
*/
function setIncomingVariables() {
	var methodName = "setIncomingVariables";
	trace("enter", methodName);

	// The request type - if none available assume 'resource'
	temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("request_type", "urn:ibm:names:ITFIM:oauth:request");
	if (temp_attr != null && temp_attr.length > 0) {
		request_type = temp_attr[0];
	} else {
		request_type = "resource";
	}
	// The grant type
	grant_type = stsuu.getContextAttributes().getAttributeValueByNameAndType("grant_type", "urn:ibm:names:ITFIM:oauth:body:param");

	// The username
	username = stsuu.getContextAttributes().getAttributeValueByNameAndType("username", "urn:ibm:names:ITFIM:oauth:body:param");

	// The password
	password = stsuu.getContextAttributes().getAttributeValueByNameAndType("password", "urn:ibm:names:ITFIM:oauth:body:param");

	// The auth_operation_type/operation
	auth_operation_type = stsuu.getContextAttributes().getAttributeValueByNameAndType("auth_operation_type", "urn:ibm:names:ITFIM:oauth:body:param");

	trace("exit", methodName);
}

/**
* This method obtains a header value from the incoming request. 
* This requires (and assumes) that the advanced tuning parameter sps.httpRequestClaims.enabled is set to true 
* and that the sps.httpRequestClaims.filterSpec advanced tuning parameter includes headers. 
*
* @method getHeader
*/
function getHeader(headerName){
	var methodName = "getHeader";
	trace("enter", methodName);

	trace("info", methodName, stsuu.toString());

	var returnedHeader = null;

	var rstr = stsuu.getRequestSecurityToken();

	var claims = rstr.getAttributeByName("Claims");

	var nodes = claims.getNodeValues();
	var claimsNode = null;
	for( var j = 0; j < nodes.length; j++) {
		if(nodes[j].getNodeName() == "wst:Claims") {
		  claimsNode = nodes[j].getFirstChild();
		  break;
		}
	}

	var headers = null;

	if(claimsNode != null) {
		var child = claimsNode.getFirstChild();
		while (child.getNodeName() != "Headers") {
		  child = child.getNextSibling();
		}
		headers = child;
	}

	if (headers != null) {
		var headerList = headers.getChildNodes();

		for(var k = 0; k < headerList.getLength(); k++) {
			var elem = headerList.item(k);
			var name = elem.getAttribute("Name");
			// We're assuming one value child
			var value = elem.getFirstChild().getTextContent();
			// trace("info", methodName, "HEADERS: " + elem + " " + name + " " + value);
			if(name.equalsIgnoreCase(headerName)){
				returnedHeader = value;
			}
		}
	}

	trace("exit", methodName);
	return returnedHeader;
}

function main_fp_pin_flow(){
	var methodName = "pre_main_fp_pin_flow";
	trace("enter", methodName);

	try {

		setIncomingVariables();

		trace("info", methodName, "The auth_operation_type: " + auth_operation_type);		
		trace("info", methodName, "Request_type: "+ request_type + " grant_type: " + grant_type + " username: " +username + " password: " + password);

		var isAuthenticated = null;

		if (request_type == "access_token" && (grant_type == "password")) {
			// Throw an exception if no username or password was defined
			if (username == null || password == null) {
				// use throwSTSUserMessageException to return the exception message in request's response
				trace("error", methodName, "PreDI001","PreCI001");
				//OAuthMappingExtUtils.throwSTSUserMessageException("No username/password.");
			}

			var isAuthenticated = false;
			try {
				var userLookupHelper = new UserLookupHelper();
				/* 
				 * First we try initialising the lookup helper with the Username Password
				 * mechanism. If that doesn't work, then we try sourcing it from the
				 * ldap.conf, if that doesn't work, we fail. 
				 *
				 * This can be overriden via the boolean 'force_ldap_conf' at the
				 * beginning of this file
				 *
				 */
				if(!force_ldap_conf) {
					userLookupHelper.init(true);
					if(!userLookupHelper.isReady()) {
						userLookupHelper = new UserLookupHelper();
						userLookupHelper.init(false);
					} 
				} else {
					userLookupHelper.init(false);
				}

				if(userLookupHelper.isReady()) {

					var user = userLookupHelper.getUser(username);
					if(user != null) {
						isAuthenticated = user.authenticate(password);
					}
				} else {
					trace("error", methodName, "PreDI001","PreCI001");
					//OAuthMappingExtUtils.throwSTSUserMessageException("Invalid username/password mechanism configuration. Authentication failed.");
				}
			} catch (ex) {
				// Throw an exception in order to stop the flow.
				trace("error", methodName, "PreDI001","PreCI001");
				//OAuthMappingExtUtils.throwSTSUserMessageException(ex.message);
			}

			if (isAuthenticated) {
				IDMappingExtUtils.traceString("Authentication successful.");
			} else {
				// Throw an exception when authentication failed in order to stop the flow.
				trace("error", methodName, "PreDI001","PreCI001");
				//OAuthMappingExtUtils.throwSTSUserMessageException("Invalid username/password. Authentication failed.");
			}
		
		}else if (grant_type == "refresh_token") {

			isAuthenticated = true;  //TBD:  Authenticate user credentials here

			if (isAuthenticated) {
				//Since touch ID is based on the signature from signed refresh token to process the signature in post mapping refresh token current refresh token has to be saved in an attribute
				var current_refresh_token = stsuu.getContextAttributes().getAttributeValueByNameAndType("refresh_token", "urn:ibm:names:ITFIM:oauth:body:param");
				var current_access_token = stsuu.getContextAttributes().getAttributeValueByNameAndType("access_token", "urn:ibm:names:ITFIM:oauth:body:param");

			 	trace("info", methodName, "Current Access Tokens; current_refresh_token: " + current_refresh_token + " current_access_token: " + current_access_token);
			 	trace("info", methodName, "Setting existing_refresh_token to current_refresh_token");
				
				
			 	if(current_refresh_token){
					stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("existing_refresh_token", "urn:ibm:names:ITFIM:oauth:response:attribute", current_refresh_token));
				}
				if (current_access_token!=null && auth_operation_type == "ENROLFINGERPRINT"){
					var token = OAuthMappingExtUtils.getToken(current_access_token);
					if(token!=null && !token.isExpired()){
						stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("existing_access_token_stateid", "urn:ibm:names:ITFIM:oauth:response:attribute", token.getStateId()));
					}
				}
				
			} else {
				PluginUtils.logAuditEvent(username, "Invalid username/password. Authentication failed.", false);
				// Throw an exception when authentication failed in order to stop the flow.
				trace("error", methodName, "PreDI001","PreCI001");
			}
		}else{
			//trace("error", methodName, "PreDI003","PreCI002");
		}
	} catch (e) {
		trace("info", methodName, "An error occured with the security flow: " + e.message);
		handleError(e.message);
	}

	trace("exit", methodName);
}

/**
 * ROPC scenario using a user registry for verification of the username 
 * and password.
 */

if (fp_pin_ropc) {

	main_fp_pin_flow();
}
