/* Valid workflows:
* 	- REGISTER - First time registration with username/pasword
*   - ENROL PIN - Enrol the PIN and associates with the OAuth grant in the ISAM DB
* 	- VALIDATE PIN  - Validates the refresh token and PIN and issues a new refresh and access token
* 	- ENROL FINGERPRINT - Enrol the fingerprint public key from the device to ISAM DB
* 	- VALIDATE FINGEPRINT - Validates the refresh token and fingerprint signature and issues new a refresh and access token pair
* 	- UN-ENROL FINGERPRINT - De-registeres any fingerprint that is enrolled and issues new refresh token and access token based on previous fingerprint validation
* 	- LOGOUT - Deletes all associated refresh and access tokens
* 	- RESOURCE FLOW - Validates access tokens and also checks for inactivity
*
* @author: Jared Page, Asha Shivalingaiah & Trevor Norvill
*/
importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Headers);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
importClass(Packages.java.util.ArrayList);
importClass(Packages.java.util.HashMap);
importClass(Packages.com.ibm.security.access.signing.SigningHelper);
importClass(Packages.com.tivoli.am.fim.base64.BASE64Utility);

// ========================================= GLOBAL VARIABLES ================================================

trace("info", "entry", "============================ Inside Post Mapping rule ============================");


//Standard OAuth Variabless
var state_id = null;
var request_type = null;
var grant_type = null;
var username = null;
var password = null;
var client_id = null;
var access_token = null;

//Helper variables
var next_valid_op = null;
var temp_attr = null;
var auth_operation_type = null;

//Maximum incorrect attempts allowed for PIN or UserName Password validation
var MAX_ALLOWED_INCORRECT_PIN_ATTEMPTS = 5;
//PIN incorrect attempt expiry timeout in minutes
var DEFAULT_INCORRECT_PIN_ATTEMPT_EXPIRY_TMO = 60;
//Access Token inactivity timeout in MILLISECONDS


//Fingerprint variables
var publicKey = null;
var signedData = null;
var refresh_token = null;
var access_token = null;

//PIN variables
var PIN = null;
var oldPIN = null;
var newPIN = null;

// ========================================= ^^ GLOBAL VARIABLES ^^ ================================================

// ========================================= HELPER FUNCTIONS ================================================

var trace_pipe = "|||";


/**
* A global function for outputting consistent trace for the mapping rule. 
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
		IDMappingExtUtils.traceString(enterTracePrepend + " " + methodName + " " + enterTraceAppend);
	} else if (type == "exit") {
		IDMappingExtUtils.traceString(exitTracePrepend + " " + methodName + " " + exitTraceAppend);
	} else if (type == "error") {
		IDMappingExtUtils.traceString(errorTracePrepend + " " + methodName + " " + message + " " + infoTraceAppend);
		OAuthMappingExtUtils.throwSTSException("post_token_mapping_rule:"+methodName+"() " + trace_pipe + message + trace_pipe + second_message);
	} else if (type == "warning") {
		IDMappingExtUtils.traceString(warningTracePrepend + " " + methodName + " " + message + " " + infoTraceAppend);
	} else if (type == "success") {
		IDMappingExtUtils.traceString(successTracePrepend + " " + methodName + " " + message + " " + infoTraceAppend);
	} else if (type == "info") {
		IDMappingExtUtils.traceString(infoTracePrepend + " " + methodName + " " + message + " " + infoTraceAppend);
	}
}

/**
* This method is the main error handler function. It runs when the global try->catch handles an error. 
* It does the following things:
*	1. Add
* 		- state_id
*		- auth_ext_msg
* 		- auth_ext_result
* 		- 
* 		_ auth_ext_error_message
* 		_ auth_ext_error_debug_message
* 		_ auth_ext_error_code
* 		_ auth_ext_error_stacktrace
* 		attributes to AAC response.
*	2. Remove:
* 		_ access_token
* 		_ expires_in
* 		_ token_type
* 		_ scope
		attributes from the AAC response. 
*	3. Add Super ID and Banket IDs to the response (if they are available).
*
* @method handleError
* @param {String} str - state_id - the current state_id UID of the flow. 
* @param {Object} obj - error_message - the error_message object
* @return {null or STSException} null
*/
function handleError(state_id, error_message) {
	var methodName = "handleError";
	trace("enter", methodName);

		var error_stacktrace = error_message.split(trace_pipe).length == 3 ? error_message.split(trace_pipe)[0] : "com.tivoli.am.fim.trustserver.sts.STSException: post_token_mapping_rule:1153:handleError()";
		var debug_error_code = error_message.split(trace_pipe).length == 3 ? error_message.split(trace_pipe)[1] : "DIAMP000";
		var client_error_code = error_message.split(trace_pipe).length == 3 ? error_message.split(trace_pipe)[2] : "CIAMP000";
		var error_debug_message = errorCodeToDebugMessageLookupTable(debug_error_code);
		var error_message_client = errorCodeToClientMessageLookupTable(client_error_code);

		stsuu.addContextAttribute(new Attribute("state_id", "urn:ibm:names:ITFIM:oauth:response:attribute", state_id));
		stsuu.addContextAttribute(new Attribute("auth_ext_result", "urn:ibm:names:ITFIM:oauth:response:attribute", "false"));
		stsuu.addContextAttribute(new Attribute("auth_ext_error_message", "urn:ibm:names:ITFIM:oauth:response:attribute", error_message_client));
		stsuu.addContextAttribute(new Attribute("auth_ext_error_debug_message", "urn:ibm:names:ITFIM:oauth:response:attribute", error_debug_message));
		stsuu.addContextAttribute(new Attribute("auth_ext_error_code", "urn:ibm:names:ITFIM:oauth:response:attribute", debug_error_code));
		stsuu.addContextAttribute(new Attribute("auth_ext_error_stacktrace", "urn:ibm:names:ITFIM:oauth:response:attribute", error_stacktrace));

		addsuperAndBankAttributesToResponse(super_omnitureId, banknet_immutableId, banknet_omnitureId);
		var attribute_array = ['access_token', 'expires_in', 'token_type', 'scope'];
		removeAttributes(attribute_array);
	

	trace("exit", methodName);
}






//=========== PIN FUNCTIONS ==================//
/**
* This method validates the inputted PIN against the stored ID. 
*
* @method validatePin
* @param {String} str - state_id - the current state_id UID of the flow. 
* @param {String} str - pinInput - the current user supplied PIN. 
* @return {null or STSException} null
*/
function validatePin(stateId, pinInput) {
	var methodName = "validatePin";
	trace("enter", methodName);

	var storedpin = OAuthMappingExtUtils.getAssociation(stateId, "PIN_VALUE");

	var storedIncorrectAttempt = OAuthMappingExtUtils.getAssociation(stateId, "PIN_FAILEDLOGONCOUNT");
	var storedPinLastAccessTime = OAuthMappingExtUtils.getAssociation(stateId, "PIN_SUCCESSFULLOGONTIMESTAMP");

	IDMappingExtUtils.traceString("MAPPINGMODULE: PIN AUTH values are stored vs input" + storedpin + "vs" + pinInput);
	if (comparePIN(pinInput, storedpin)) {
		//if (storedpin.equals(pinInput)) {
		trace("info", methodName, "MAPPINGMODULE: PIN AUTH SUCCESS");
		OAuthMappingExtUtils.associate(state_id, "PIN_FAILEDLOGONCOUNT", 0);
		var d = new Date();
		OAuthMappingExtUtils.associate(state_id, "PIN_SUCCESSFULLOGONTIMESTAMP", d.getTime());
		return true;
	} else {
		trace("info", methodName, "MAPPINGMODULE: PIN AUTH FAILED");
		if (storedIncorrectAttempt != null) {
			storedIncorrectAttempt = parseInt(storedIncorrectAttempt) + 1;
			OAuthMappingExtUtils.associate(state_id, "PIN_FAILEDLOGONCOUNT", storedIncorrectAttempt);
			//failed Logon timestamp update
			var d = new Date();
			OAuthMappingExtUtils.associate(state_id, "PIN_FAILEDLOGONTIMESTAMP", d.getTime());

			//Expiry timeout to reset the incorrect attempt to zero

			//OAuthMappingExtUtils.associate(state_id, "PIN_LOGONLOCKEXPIRESTIMESTAMP", todo(DEFAULT_INCORRECT_PIN_ATTEMPT_EXPIRY_TMO));
			if (storedIncorrectAttempt >= MAX_ALLOWED_INCORRECT_PIN_ATTEMPTS) {

				OAuthMappingExtUtils.associate(state_id, "PIN_STATUS", "PIN_LOCKED");
				OAuthMappingExtUtils.associate(state_id, "STATUS_REASONCODE", "INCORRECTATTEMPT001");
				OAuthMappingExtUtils.associate(state_id, "SUPPORT_NOTES", "User crossed incorrect attempt");
			}

		} else {
			OAuthMappingExtUtils.associate(state_id, "PIN_FAILEDLOGONCOUNT", 1);
		}
		return false;
	}
}


/**
* Function to compare the pin input in request to stored pin in the database.
*
* @method comparePIN
* @param {String} str - inputPIN - the user supplied PIN. 
* @param {String} str - storedPIN - the stored PIN. 
* @return {Boolean} bool - comparison - Whether or not the PIN is correct with the currently stored PIN. 
*/
function comparePIN(inputPIN, storedPIN) {
	var methodName = "comparePIN";
	trace("enter", methodName);


	return inputPIN == storedPIN ? true : false;

	trace("exit", methodName);
}

/**
* This is the function to perform basic PIN policy checks
*
* @method canWeSetPin
* @param {String} str - pinInput - the current user supplied PIN. 
* @return {Boolean} bool - pinallowed - Whether or not the PIN is allowed to be set. 
*/
function canWeSetPin(pinInput) {
	var methodName = "canWeSetPin";
	trace("enter", methodName);
	trace("info", methodName, pinInput);
	if (pinInput.length() == 4) {
		var regex = "[0-9]+";
		if (pinInput.matches(regex)) {
			trace("info", methodName, "POSTMAPPING1: Here1");
			return true;
		} else {
			trace("info", methodName, "POSTMAPPING1: Here2");
			return false;
		}
	} else {
		return false;
	}

	trace("exit", methodName);
}
//=========== ^^^ PIN FUNCTIONS ^^^ ==================//



/**
* Common function to remove given attribute set form the AAC response.
* @param {Array} arr - attribute_array - the attributes to removed.
* @return {null or STSException} null
*/
function removeAttributes(attribute_array) {
	var methodName = "removeAttributes";
	trace("enter", methodName);

	for (var i = 0; i < attribute_array.length; i++) {
		stsuu.getContextAttributes().removeAttributeByNameAndType(attribute_array[i], "urn:ibm:names:ITFIM:oauth:response:attribute");
	}

	trace("exit", methodName);
}


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

	// The state id handle
	state_id = stsuu.getContextAttributes().getAttributeValueByNameAndType("state_id", "urn:ibm:names:ITFIM:oauth:state");

	if (state_id == null || state_id == "undefined"){
		var access_token_fromrequest = stsuu.getContextAttributes().getAttributeValueByNameAndType("access_token", "urn:ibm:names:ITFIM:oauth:param");
		var token = OAuthMappingExtUtils.getToken(access_token_fromrequest);
		state_id = token.getStateId();
	}

	// The client ID
	client_id = stsuu.getContextAttributes().getAttributeValueByNameAndType("client_id", "urn:ibm:names:ITFIM:oauth:body:param");

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

	
	// The PIN
	PIN = stsuu.getContextAttributes().getAttributeValueByNameAndType("PIN", "urn:ibm:names:ITFIM:oauth:body:param");

	// The auth_operation_type/operation
	auth_operation_type = stsuu.getContextAttributes().getAttributeValueByNameAndType("auth_operation_type", "urn:ibm:names:ITFIM:oauth:body:param");

	// oldPIN
	oldPIN = stsuu.getContextAttributes().getAttributeValueByNameAndType("oldPIN", "urn:ibm:names:ITFIM:oauth:body:param");

	// newPIN
	newPIN = stsuu.getContextAttributes().getAttributeValueByNameAndType("newPIN", "urn:ibm:names:ITFIM:oauth:body:param");

	// The next URI
	temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("next_valid_op", "urn:ibm:names:ITFIM:oauth:response:attribute");
	if (temp_attr != null && temp_attr.length > 0) {
		next_valid_op = temp_attr[0];
	} else {
		next_valid_op = "register";
	}


	refresh_token = stsuu.getContextAttributes().getAttributeValueByNameAndType("refresh_token", "urn:ibm:names:ITFIM:oauth:body:param");
	access_token = stsuu.getContextAttributes().getAttributeValueByNameAndType("access_token", "urn:ibm:names:ITFIM:oauth:body:param");

	var i = stsuu.getContextAttributes().getAttributeIterator();
	while (i.hasNext()) {
		var attr = i.next();
		var name = attr.getName();
		var type = attr.getType();
		var value = stsuu.getContextAttributes().getAttributeValuesByName(name)[0];
		trace("info", methodName, " **************************************");
		trace("info", methodName, "Context attributes + " + name + " " + type + " " + value);
		trace("info", methodName, " **************************************");

	}

	trace("exit", methodName);
}



/**
* Function to delete all access tokens for given state_id.
*
* @method deleteAllAccessTokensForStateID
* @param {String} str - state_id - the current state_id UID of the flow. 
* @return {null or STSException} null
*/
function deleteAllAccessTokensForStateID(state_id) {
	var methodName = "deleteAllAccessTokensForStateID";
	trace("enter", methodName);

	//access_token_id
	access_token_id = stsuu.getContextAttributes().getAttributeValueByNameAndType("access_token_id", "urn:ibm:names:ITFIM:oauth:response:metadata");

	// delete all access tokens with this state id.

	if (access_token_id != null) {
		OAuthMappingExtUtils.deleteToken(access_token_id);
	}

	trace("exit", methodName);
}



// ========================================= ^^^ Other functions ^^^ ================================================

// ========================================= Public / Private Key functions ================================================

/**
* Function to retrieve the seperate parts of the public key, reconstruct them, then return
* them in a contiguous string. 
*
* @method getPublicKey
* @param {String} str - state_id - the current state_id UID of the flow. 
* @return {String} str - public_key - the currently stored public key.
*/
function getPublicKey(stateId) {
	var methodName = "getPublicKey";
	trace("enter", methodName);

	var p1 = OAuthMappingExtUtils.getAssociation(stateId, "FINGERPRINT_PUBLICKEY_PART1");
	var p2 = OAuthMappingExtUtils.getAssociation(stateId, "FINGERPRINT_PUBLICKEY_PART2");
	var p3 = OAuthMappingExtUtils.getAssociation(stateId, "FINGERPRINT_PUBLICKEY_PART3");
	var p4 = OAuthMappingExtUtils.getAssociation(stateId, "FINGERPRINT_PUBLICKEY_PART4");

	var stringtoreplace = null;
	if (p1 != null) {
		stringtoreplace = p1;
		if (p2 != null) {
			stringtoreplace = stringtoreplace + p2;
			if (p3 != null) {
				stringtoreplace = stringtoreplace + p3;
				if (p4 != null) {
					stringtoreplace = stringtoreplace + p4;
				}
			}
		}
	}

	trace("exit", methodName);
	return stringtoreplace;
}

/**
* Function to store the fingerprint public key in the extra attributes table of AAC runtime
* Since the publicKey may be longer than 256 column size of the extra attributes to not affect the schema
* and keep it expendable for future usecase save as parts
*
* @method storePublicKey
* @param {String} str - state_id - the current state_id UID of the flow. 
* @param {String} str - publicKey - the public key to be stored. 
* @return {null or STSException} null
*/
function storePublicKey(stateId, publicKey) {
	var methodName = "storePublicKey";
	trace("enter", methodName);

	if (publicKey.length() < 250) {
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART1", publicKey);
	} else if (publicKey.length() >= 250 && publicKey.length() < 500) {
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART1", publicKey.substring(0, 250));
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART2", publicKey.substring(250, publicKey.length()));
	} else if (publicKey.length() >= 500 && publicKey.length() < 700) {
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART1", publicKey.substring(0, 250));
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART2", publicKey.substring(250, 450));
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART3", publicKey.substring(450, publicKey.length()));
	} else if (publicKey.length() >= 700 && publicKey.length() < 950) {
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART1", publicKey.substring(0, 250));
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART2", publicKey.substring(250, 450));
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART3", publicKey.substring(450, 700));
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART4", publicKey.substring(700, publicKey.length()));
	} else {
		trace("error", methodName, "DI035","CI000");
	}

	trace("exit", methodName);
}

/**
* Function to delete Fingerprint public key from the extra attributes table of AAC runtime
*
* @method deletePublicKey
* @param {String} str - state_id - the current state_id UID of the flow. 
* @return {null or STSException} null
*/
function deletePublicKey(stateId) {
	var methodName = "deletePublicKey";
	trace("enter", methodName);

	var p1 = OAuthMappingExtUtils.getAssociation(stateId, "FINGERPRINT_PUBLICKEY_PART1");
	var p2 = OAuthMappingExtUtils.getAssociation(stateId, "FINGERPRINT_PUBLICKEY_PART2");
	var p3 = OAuthMappingExtUtils.getAssociation(stateId, "FINGERPRINT_PUBLICKEY_PART3");
	var p4 = OAuthMappingExtUtils.getAssociation(stateId, "FINGERPRINT_PUBLICKEY_PART4");
	var stringtoreplace = null;
	if (p1 != null) {
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART1", "");
	}
	if (p2 != null) {
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART2", "");
	}
	if (p3 != null) {
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART3", "");
	}
	if (p4 != null) {
		OAuthMappingExtUtils.associate(stateId, "FINGERPRINT_PUBLICKEY_PART4", "");
	}

	trace("exit", methodName);
}

/**
* Function to validate the fingerprint signature with the publicKey 
*
* @method deletePublicKey
* @param {String} str - refToken - Token that is signed on the device 
* @param {String} str - cert -  PublicKey that is stored on device and the ISAM DB
* @param {String} str - signedData - Signature with private key and token to be verified 
* @return {null or STSException} null
*/
String.prototype.getBytes = function () {
  var bytes = [];
  for (var i = 0; i < this.length; ++i) {
    bytes.push(this.charCodeAt(i));
  }
  return bytes;
};

function getSignatureVerifyResult(refToken, cert, signedData) {
	var methodName = "getSignatureVerifyResult";
	trace("enter", methodName);

	trace("info", methodName, "Attempting to getSignatureVerifyResult");
	
	var result = false;
	//Android SDK signs with SHA256 and IOS SDK signs with SHA512 due to the lib limitations
	//https://code.google.com/p/android/issues/detail?id=210237
	//Inorder to cater for both these OS, we use this logic to update the result if either case is true 
	//Another option is to identify whether the call was from android or ios but to avoid app changes or another attribute 
	//We use this dual check 
	var resultFromSHA512 = false;
	var resultFromSHA256 = false;

	try{
		/*
		var signer512 = new SigningHelper("SHA512withRSA");

		//Defect here - Throwing error on invalid key (for example URL vs not URL safe).
		//Defect here - returns true on 256 key
		var checking512 = signer512.checkKeyB64Url(cert);
		trace("info", methodName, "Checking 512: " + checking512);

		var verify512 = signer512.verifyB64Url(refToken, signedData, cert);
		if (verify512 != null && verify512 == true) {
			resultFromSHA512 = true;
			trace("info", methodName, "Verified SHA512");
		}
		*/
		//-----

		var signer256 = new SigningHelper("SHA256withRSA");
		trace("info", methodName, "HERE1");
		var checking2560 = signer256.checkKey(cert);
		trace("info", methodName, "HERE2 " + checking2560);

		//var checking2561 = signer256.checkKeyB64(cert);
		//trace("info", methodName, "HERE3");
		//var checking256 = signer256.checkKeyB64(cert);
		//trace("info", methodName, "HERE4");
		//trace("info", methodName, "Checking 256: " + checking256);
		//var b64decoded_signedData = BASE64Utility.decode(signedData)
		//trace("info", methodName, "HERE5" + b64decoded_signedData);
		//var verify256 = signer256.verify(refToken.getBytes(), b64decoded_signedData.getBytes(), cert.getBytes());
		trace("info", methodName, "HERE6");
		var verify256 = signer256.verifyB64(refToken, signedData, cert);
		//var verify256 = signer256.verifyB64Url(refToken, signedData, cert);
		trace("info", methodName, "HERE7");
		if (verify256 != null && verify256 == true) {
			trace("info", methodName, "Verified SHA256");
			resultFromSHA256 = true;
		}
	} catch (e) {
		trace("error", methodName, "DI036","CI006");
	}

	//-----

	if (resultFromSHA512 == true || resultFromSHA256 == true) {
		trace("info", methodName, "Verified Signature");
		result = true;
	}
	

	trace("exit", methodName);
	//IBM TODO: FIXME : by default returning TRUE fix me 
	//return result;
	return true;
}

/**
* The user registration method handles the initial registration of a user into the mobile App
* via username/password. From this point other methods can be registered (PIN and Fingerprint)
*
* @method userRegistration
* @param {String} str - state_id - the current state_id UID of the flow. 
* @param {Object} obj - some object
* @param {requestCallback} callback - The callback that handles the response.
* @return {null or STSException} null
*/
function userRegistration(state_id, username, PIN) {
	var methodName = "userRegistration";
	trace("enter", methodName);


	try{
		if (PIN == null || !canWeSetPin(PIN)) {
			stsuu.getContextAttributes().removeAttributeByNameAndType("next_valid_op", "urn:ibm:names:ITFIM:oauth:response:attribute");
			trace("error", methodName, "DI032","CI011");
		} else {
			var existing_deviceName = OAuthMappingExtUtils.getAssociation(state_id, "DEVICEID");
			var existing_appPin = OAuthMappingExtUtils.getAssociation(state_id, "PIN_VALUE");
			trace("info", methodName, "Existing variables stored....DeviceName: " + existing_deviceName + "PIN: " + existing_appPin);
			
			//Validating if the user has already registered
			if (existing_deviceName == null & existing_appPin == null) {
				if (PIN == null) {
					trace("error", methodName, "DI033","CI012");
				}
				trace("info", methodName, "PIN set appears to be correct.");
				trace("info", methodName, "Setting the PIN_VALUE, PIN_STATUS to PIN_ESTABLISHED, the REUSERNAME and updating/setting account details and enrolment details.");

				OAuthMappingExtUtils.associate(state_id, "PIN_VALUE", PIN);
				//OAuthMappingExtUtils.associate(state_id, "PIN_VALUE", PIN);
				OAuthMappingExtUtils.associate(state_id, "PIN_STATUS", "PIN_ESTABLISHED");
				//Adding username to the extra attributes for use in logout module of refresh token since username will not be available at that time
				OAuthMappingExtUtils.associate(state_id, "REUSERNAME", username);
	
			} else {
				trace("error", methodName, "DI034","CI013");
			}
		}
	} catch (e) {
		trace("info", methodName, "An error occured: " + e.message);
		handleError(e.message);
	}

	trace("exit", methodName);
}



/**
* The PIN authentication function validates a PIN passed in the request for a given user.
* A user will pass the attempted PIN, along with optional account attributes to be updated. 
* The PIN will be validated locally - TBD
*
* @method pinAuthentication
* @param {String} str - state_id - the current state_id UID of the flow. 
* @return {null or STSException} null
*/
function pinAuthentication(state_id, PIN, stored_pin_status, fingerprintUnenrol) {
	var methodName = "pinAuthentication";
	trace("enter", methodName);

	if (fingerprintUnenrol) {
		if (validatePin(state_id, PIN)) {
			trace("info", methodName, "PIN validation success");
			trace("info", methodName, "Checking that the PIN_STATUS variable must be not null and PIN_ESTABLISHED");
			if (stored_pin_status != null && stored_pin_status == "PIN_ESTABLISHED") {
				trace("info", methodName, "PIN authentication appears to be correct.");
				trace("info", methodName, "Setting the new PREVIOUS_LASTUSED_TIMESTAMP and the AUTH_STATUS to PIN_AUTHENTICATED.");
				//if non-migrated user, uid update calls will come here
				//if new access token is issued then remove the inactivity attribute
				OAuthMappingExtUtils.associate(state_id, "PREVIOUS_LASTUSED_TIMESTAMP", "");
				//Since it is pin authentication issues access token status is set to PIN_AUTHENTICATED
				OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "");
				OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "PIN_AUTHENTICATED");
			} else {
				trace("error", methodName, "DI026","CI008");
			}
		} else {
			trace("error", methodName, "DI027","CI008");
		}
	} else {
		trace("error", methodName, "DI028","CI008");
	}
	trace("exit", methodName);
}

/**
* The PIN modification method allows the PIN to be changed. It requires the input of an old PIN and then a new one. 
* A user will pass the existing PIN, their new PIN and any optional account attributes to be updated. 
*
* @method pinModification
* @param {String} str - state_id - the current state_id UID of the flow. 
* @return {null or STSException} null
*/
function pinModification(state_id, oldPIN, newPIN, stored_pin_status) {
	var methodName = "pinModification";
	trace("enter", methodName);

		//Validate PIN
		if (validatePin(state_id, oldPIN)) {
			trace("info", methodName, "PIN validation success");
			trace("info", methodName, "Checking that the PIN_STATUS variable must be not null and PIN_ESTABLISHED");
			if (stored_pin_status != null && stored_pin_status == "PIN_ESTABLISHED") {
				trace("info", methodName, "PIN Validation successful.");
				trace("info", methodName, "newPIN" + newPIN);
				if (newPIN != null && canWeSetPin(newPIN)) {
					if (newPIN == null) {
						trace("error", methodName, "DI021","CI007");
					}
					trace("info", methodName, "PIN change appears to be correct.");
					trace("info", methodName, "Setting the new PIN_VALUE, the PIN_STATUS to PIN_ESTABLISHED, PREVIOUS_LASTUSED_TIMESTAMP and the AUTH_STATUS to PIN_AUTHENTICATED.");

					OAuthMappingExtUtils.associate(state_id, "PIN_VALUE", newPIN);
					//OAuthMappingExtUtils.associate(state_id, "PIN_VALUE", newPIN);
					OAuthMappingExtUtils.associate(state_id, "PIN_STATUS", "PIN_ESTABLISHED");
					//if new access token is issued then remove the inactivity attribute
					OAuthMappingExtUtils.associate(state_id, "PREVIOUS_LASTUSED_TIMESTAMP", "");
					//Since it is pin authentication issues access token status is set to PIN_AUTHENTICATED
					OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "");
					OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "PIN_AUTHENTICATED");

				} else {
					trace("error", methodName, "DI022","CI007");
				}
			} else {
				trace("error", methodName, "DI023","CI007");
			}
		} else {
			trace("error", methodName, "DI024","CI007");
		}

	trace("exit", methodName);
}

/**
* The enrolment for fingerprint method allows the user to store their public key for their device on the server. 
* This public key is unlockable by the Fingerprint sensor on a mobile device, and hence can be used for fingerprint verification.
* A user will pass a valid public key and a signed refresh token (with the private key) for fingerprint registration. 
* A user must have already logged in with their PIN to be able to register a fingerprint. 
*
* @method fingerprintEnrolment
* @param {String} str - state_id - the current state_id UID of the flow. 
* @param {String} str - stored_pin_status - the current status of the session in relation to the PIN. 
* @return {null or STSException} null
*/
function fingerprintEnrolment(state_id, stored_pin_status) {
	var methodName = "fingerprintEnrolment";
	trace("enter", methodName);

	trace("info", methodName, "Checking that the PIN_STATUS variable must be not null and PIN_ESTABLISHED");
	if (stored_pin_status != null && stored_pin_status == "PIN_ESTABLISHED") {
		//Validate Access token string and expires for access token 
		var access_token_fromrequest = stsuu.getContextAttributes().getAttributeValueByNameAndType("access_token", "urn:ibm:names:ITFIM:oauth:body:param");
		var prev_access_token_stateid_from_prerule = stsuu.getContextAttributes().getAttributeValueByNameAndType("existing_access_token_stateid", "urn:ibm:names:ITFIM:oauth:response:attribute");
        //trace("info", methodName, "INFO:" + access_token_fromrequest + "EXISTING " + my_existing_refresh_token);
		
		//var signer256 = new SigningHelper("SHA256withRSA");
		//trace("info", "INTOUCHIDENROLTEST1", "START**********************");
		//var checking2561 = signer256.checkKeyB64(stsuu.getContextAttributes().getAttributeValueByNameAndType("publicKeywithourheadfootNOb64", "urn:ibm:names:ITFIM:oauth:body:param"));
		//trace("info", "LEVEl1", checking2561);
		//var checking2561 = signer256.checkKey((stsuu.getContextAttributes().getAttributeValueByNameAndType("publicKey1", "urn:ibm:names:ITFIM:oauth:body:param")).getBytes());
		//var checking2562 = signer256.checkKeyB64(stsuu.getContextAttributes().getAttributeValueByNameAndType("publicKey2", "urn:ibm:names:ITFIM:oauth:body:param"));
		//var checking2563 = signer256.checkKeyB64(stsuu.getContextAttributes().getAttributeValueByNameAndType("publicKey3", "urn:ibm:names:ITFIM:oauth:body:param"));
		//var checking2564 = signer256.checkKeyB64(stsuu.getContextAttributes().getAttributeValueByNameAndType("publicKey4", "urn:ibm:names:ITFIM:oauth:body:param"));
		//trace("info", "LEVEl1", checking2562);
		//var checking2563 = signer256.checkKeyB64(stsuu.getContextAttributes().getAttributeValueByNameAndType("publicKeywithourheadfootb64", "urn:ibm:names:ITFIM:oauth:body:param"));
		//trace("info", "LEVEl1", checking2563);
		
		//trace("info", "INTOUCHIDENROLTEST1", "END**********************");
		if (access_token_fromrequest != null) {

			//var token = OAuthMappingExtUtils.getToken(access_token_fromrequest);
			
			//var token2 = OAuthMappingExtUtils.getToken(my_existing_refresh_token);
			
			//For additional re-validation per requirement state_id validation is included
			//This valdation checks that - access token was present in the request, was valid at the time of authentication and has a stateid associated 
			if (prev_access_token_stateid_from_prerule!=null) {
				if (state_id.equals(prev_access_token_stateid_from_prerule) && state_id != null && prev_access_token_stateid_from_prerule != null) {

					//Get PublicKey from request
					publicKey = stsuu.getContextAttributes().getAttributeValueByNameAndType("publicKey", "urn:ibm:names:ITFIM:oauth:body:param");

					//Get signedData 
					signedData = stsuu.getContextAttributes().getAttributeValueByNameAndType("signedData", "urn:ibm:names:ITFIM:oauth:body:param");
			
					//Get RefreshToken that was used in the signature, will be the previous token since at this stage a new refresh token is issued already
					var refresh_token_fromPrev = stsuu.getContextAttributes().getAttributeValueByNameAndType("existing_refresh_token", "urn:ibm:names:ITFIM:oauth:response:attribute");
				
					trace("info", methodName, "Attributes; PublicKey: " + publicKey + " SignedData: " + signedData + " RefreshToken: " + refresh_token_fromPrev);

					if (signedData != null && refresh_token_fromPrev != null && publicKey != null) {
						//For sanity check on public Key we do a signature verification 
						if (getSignatureVerifyResult(refresh_token_fromPrev, publicKey, signedData)) {
							trace("info", methodName, "Signature appears to be correct.");
							trace("info", methodName, "Setting the FINGERPRINT_STATUS to FINGERPRINT_ESTABLISHED & the AUTH_STATUS to NONE. Storing the public key.");
							//Store fingerprint information into the AAC runtime database
							storePublicKey(state_id, publicKey);
							OAuthMappingExtUtils.associate(state_id, "FINGERPRINT_STATUS", "FINGERPRINT_ESTABLISHED");
							//Since it is pin authentication issues access token status is set to NONE since pin was'nt authenticated, also fingerprint was just registered
							// OAuthMappingExtUtils.disassociate(state_id, "AUTH_STATUS");
							OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "NONE");
						} else {
							trace("error", methodName, "DI015","CI006");
						}
					} else {
						trace("error", methodName, "DI016","CI006");
					}
				} else {
					trace("error", methodName, "DI017","CI006");
				}
			}else{
				trace("error", methodName, "DI018","CI006");
			}
		} else {
			trace("error", methodName, "DI019","CI006");
		}
	} else {
		trace("error", methodName, "DI020","CI006");
	}
	trace("exit", methodName);
}

/**
* The fingerprint authentication method allows for the validation of a previously registered public key (unlocked by a fingerprint).
* An authentiation is performed by a user passing their refresh_token and the signed version of the refresh token (via the private key).
* This data is then validating using the previously registered stored public key. 
* A user must have already registered their fingeprint to be able to authenticate. 
* 
* @method fingerprintAuthentication
* @param {String} str - state_id - the current state_id UID of the flow. 
* @param {String} str - stored_pin_status - the current status of the session in relation to the PIN. 
* @return {null or STSException} null
*/
function fingerprintAuthentication(state_id, stored_pin_status) {
	var methodName = "fingerprintAuthentication";
	trace("enter", methodName);

	trace("info", methodName, "Checking that the PIN_STATUS variable must be not null and PIN_ESTABLISHED");
	if (stored_pin_status != null && stored_pin_status == "PIN_ESTABLISHED") {

		var stored_fingerprint_status = OAuthMappingExtUtils.getAssociation(state_id, "FINGERPRINT_STATUS");

		trace("info", methodName, "Checking that the stored FINGERPRINT_STATUS variable must be not null and FINGERPRINT_ESTABLISHED");
		if (stored_fingerprint_status != null && stored_fingerprint_status == "FINGERPRINT_ESTABLISHED") {

			//Get publicKey from DB
			var stored_fingerprint_publickey = getPublicKey(state_id);

			//Get signedData 
			var signedData = stsuu.getContextAttributesAttributeContainer().getAttributeValueByNameAndType("signedData", "urn:ibm:names:ITFIM:oauth:body:param");
			trace("info", methodName, "signedData: " + signedData);

			//Get RefreshToken that was used in the signature, will be the previous token since at this stage a new refresh token is issued already
			var refresh_token_fromPrev = stsuu.getContextAttributes().getAttributeValueByNameAndType("existing_refresh_token", "urn:ibm:names:ITFIM:oauth:response:attribute");
		
			trace("info", methodName, "refresh_token_fromPrev: " + refresh_token_fromPrev);

			if (signedData != null && refresh_token_fromPrev != null && stored_fingerprint_publickey != null) {
				if (getSignatureVerifyResult(refresh_token_fromPrev, stored_fingerprint_publickey, signedData)) {
					trace("info", methodName, "Signature appears to be correct.");
					trace("info", methodName, "Setting the AUTH_STATUS to FINGERPRINT_AUTHENTICATED.");
					//Since it is pin authentication issues access token status is set to FINGERPRINT_AUTHENTICATED
					OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "");
					OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "FINGERPRINT_AUTHENTICATED");
				} else {
					trace("error", methodName, "DI011","CI005");
				}
			} else {
				trace("error", methodName, "DI012","CI005");
			}
		} else {
			trace("error", methodName, "DI013","CI005");
		}
	} else {
		trace("error", methodName, "DI014","CI005");
	}
	trace("exit", methodName);
}

/**
* The un-enrolment for fingerprint method allows the user to delete their public key for their device on the server. 
* A user must first authenticate with their currently enroled fingerprint to un-enrol it. 
* An authentiation is performed by a user passing their refresh_token and the signed version of the refresh token (via the private key).
* A user must have already registered their fingeprint to be able to de-register. 
*
* @method fingerprintUnenrol
* @param {String} str - state_id - the current state_id UID of the flow. 
* @param {String} str - stored_pin_status - the current status of the session in relation to the PIN. 
* @return {null or STSException} null
*/
function fingerprintUnenrol(state_id, stored_pin_status, deregistrationmethod) {
	var methodName = "fingerprintUnenrol";
	trace("enter", methodName);

	trace("info", methodName, "Checking that the PIN_STATUS variable must be not null and PIN_ESTABLISHED");
	if (stored_pin_status != null && stored_pin_status == "PIN_ESTABLISHED") {

		var stored_fingerprint_status = OAuthMappingExtUtils.getAssociation(state_id, "FINGERPRINT_STATUS");

		trace("info", methodName, "Checking that the stored FINGERPRINT_STATUS variable must be not null and FINGERPRINT_ESTABLISHED");
		if (stored_fingerprint_status != null && stored_fingerprint_status == "FINGERPRINT_ESTABLISHED") {

			if (deregistrationmethod == "PIN"){

				pinAuthentication(state_id, PIN, stored_pin_status, true);
				trace("info", methodName, "PIN appears to be correct.");
				trace("info", methodName, "Deleting the Fingerprint Registration Status & setting the AUTH_STATUS to PIN_AUTHENTICATED.");
				//Since it is pin authentication issues access token status is set to FINGERPRINT_AUTHENTICATED
				OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "");
				OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "PIN_AUTHENTICATED");
				//Delete Public Key and FINGERPRINT registration status
				deletePublicKey(state_id)
				OAuthMappingExtUtils.associate(state_id, "FINGERPRINT_STATUS", "");

			}else{
				//Get publicKey from DB
				var stored_fingerprint_publickey = getPublicKey(state_id);

				//Get signedData 
				temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("signedData", "urn:ibm:names:ITFIM:oauth:body:param");
				if (temp_attr != null && temp_attr.length > 0) {
					signedData = temp_attr[0];
				}

				//Get RefreshToken that was used in the signature, will be the previous token since at this stage a new refresh token is issued already
				var refresh_token_fromPrev = null;
				temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("existing_refresh_token", "urn:ibm:names:ITFIM:oauth:response:attribute");
				if (temp_attr != null && temp_attr.length > 0) {
					refresh_token_fromPrev = temp_attr[0];
				}

				if (signedData != null && refresh_token_fromPrev != null && stored_fingerprint_publickey != null) {
					if (getSignatureVerifyResult(refresh_token_fromPrev, stored_fingerprint_publickey, signedData)) {
						trace("info", methodName, "Signature appears to be correct.");
						trace("info", methodName, "Deleting the Fingerprint Registration Status & setting the AUTH_STATUS to PIN_AUTHENTICATED.");
						//Since it is pin authentication issues access token status is set to FINGERPRINT_AUTHENTICATED
						OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "");
						OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "PIN_AUTHENTICATED");
						//Delete Public Key and FINGERPRINT registration status
						deletePublicKey(state_id)
						OAuthMappingExtUtils.associate(state_id, "FINGERPRINT_STATUS", "");
					} else {
						trace("error", methodName, "DI007","CI004");
					}
				} else {
					trace("error", methodName, "DI008","CI004");
				}
			}
		} else {
			trace("error", methodName, "DI009","CI004");
		}
	} else {
		trace("error", methodName, "DI010","CI004");
	}
	trace("exit", methodName);
}

/**
* The logout function will destroy the session and any attributes associated with it. 
* A user must have already logged in to logout. 
*
* @method logout
* @return {null or STSException} null
*/
function logout(state_id) {
	var methodName = "logout";
	trace("enter", methodName);

	trace("info", methodName, "Attempting to delete all the tokens for the given state_id: " + state_id);
	//Delete tokens
	deleteAllAccessTokensForStateID(state_id);

	trace("info", methodName, "Setting the AUTH_STATUS to NONE");
	//Since this is log out AUTH_STATUS is set to NONE
	OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "");
	OAuthMappingExtUtils.associate(state_id, "AUTH_STATUS", "NONE");

	trace("info", methodName, "Removing all response attributes");
	//Remove response attributes
	stsuu.getContextAttributes().removeAttributeByNameAndType("access_token", "urn:ibm:names:ITFIM:oauth:response:attribute");
	stsuu.getContextAttributes().removeAttributeByNameAndType("expires_in", "urn:ibm:names:ITFIM:oauth:response:attribute");
	stsuu.getContextAttributes().removeAttributeByNameAndType("token_type", "urn:ibm:names:ITFIM:oauth:response:attribute");
	stsuu.getContextAttributes().removeAttributeByNameAndType("scope", "urn:ibm:names:ITFIM:oauth:response:attribute");
	stsuu.getContextAttributes().removeAttributeByNameAndType("state_id", "urn:ibm:names:ITFIM:oauth:response:attribute");
    stsuu.getContextAttributes().removeAttributeByNameAndType("existing_refresh_token", "urn:ibm:names:ITFIM:oauth:response:attribute");
    stsuu.getContextAttributes().removeAttributeByNameAndType("refresh_token", "urn:ibm:names:ITFIM:oauth:response:attribute");
	trace("exit", methodName);
}

/**
* The resource flow method handles the use cause when the access token is already vlaidated for the token string and for 
* the absolute expiry. 
* The method validates that the access_token also has a AUTH_STATUS assocaited with it (PIN or FINGERPRINT).
*
* @method resourceFlow
* @param {String} str - state_id - the current state_id UID of the flow. 
* @return {null or STSException} null
*/
function resourceFlow(state_id) {
	var methodName = "resourceFlow";
	trace("enter", methodName);

	trace("info", methodName, "The state_id: " + state_id);

		trace("info", methodName, "The token was found to be active/valid");
		trace("info", methodName, "Checking that the AUTH_STATUS variable must be not null and XYZ_AUTHENTICATED");
		var auth_status = OAuthMappingExtUtils.getAssociation(state_id, "AUTH_STATUS")
		trace("info", methodName, "The AUTH_STATUS variable is valid: " + auth_status);
		if (auth_status != null && (auth_status == "PIN_AUTHENTICATED" || auth_status == "FINGERPRINT_AUTHENTICATED")) {
			trace("info", methodName, "The AUTH_STATUS variable is valid: " + auth_status);
		} else {
			stsuu.addContextAttribute(new Attribute("authorized", "urn:ibm:names:ITFIM:oauth:response:decision", false));
			trace("error", methodName, "DI005","CI003");
		}
	trace("exit", methodName);
}

/**
* The session flow method handles the use case when the access token is validated for the token string and for 
* the absolute expiry.
* In exchange creates a web session cookie and sends in response attributes
*
* @method sessionFlow
* @param {String} str - state_id - the current state_id UID of the flow. 
* @return {null or STSException} null
*/
function sessionFlow(state_id) {
	var methodName = "sessionFlow";
	trace("enter", methodName);

	trace("info", methodName, "The state_id: " + state_id);
	var stsuuAttrs = stsuu.getAttributeContainer();
	stsuuAttrs.setAttribute(new Attribute("authenticatedBy",null,"OAuth Session Endpoint"));
	//var redir = new Attribute("itfim_override_targeturl_attr", "urn:ibm:names:ITFIM:5.1:accessmanager","/webpage.html");
	//stsuu.addAttribute(redir);
	

		trace("info", methodName, "The token was found to be active/valid");
		trace("info", methodName, "Checking that the AUTH_STATUS variable must be not null and XYZ_AUTHENTICATED");

	trace("exit", methodName);
}

// ========================================= ^^ Security Flows ^^ ================================================

function main_fp_pin_flow() {
	var methodName = "post_main_fp_pin_flow";
	trace("enter", methodName);

	setIncomingVariables();

	if (request_type == "access_token") {

		trace("info", methodName, "Determined the request is an access_token type.");
		trace("info", methodName, "The grant type? " + grant_type);
		trace("info", methodName, "The state_id " + state_id);

		if (grant_type == "password" && state_id != null) {

			trace("info", methodName, "Determined the request is a password grant_type request. This is a brand new registration.");
			userRegistration(state_id, username, PIN);

		} else if (grant_type == "refresh_token" && state_id != null) {

			trace("info", methodName, "Determined the request is a refresh_token grant_type request. This is an existing device making a request.");



			trace("info", methodName, "Trying a security flow");

			try {
				if (auth_operation_type != null) {

					trace("info", methodName, "Security flow type is: " + auth_operation_type);

					var stored_pin_status = OAuthMappingExtUtils.getAssociation(state_id, "PIN_STATUS");
					var existing_deviceName = OAuthMappingExtUtils.getAssociation(state_id, "DEVICEID");
					var existing_appPin = OAuthMappingExtUtils.getAssociation(state_id, "PIN_VALUE");

					trace("info", methodName, "Existing variables stored....PinStatus: " + stored_pin_status +  "PIN: " + existing_appPin);

					if (stored_pin_status == "PIN_LOCKED") {
						trace("info", methodName, "The PIN state has been locked");
						stsuu.addContextAttribute(new Attribute("state_id", "urn:ibm:names:ITFIM:oauth:response:attribute", state_id));
						trace("error", methodName, "DI001","CI001", true);
					} else {
						if (auth_operation_type == "CHANGEPIN") {
							pinModification(state_id, oldPIN, newPIN, stored_pin_status);
						} else if (auth_operation_type == "VALIDATEPIN") {
							pinAuthentication(state_id, PIN, stored_pin_status, true);
						} else if (auth_operation_type == "ENROLFINGERPRINT") {
							fingerprintEnrolment(state_id, stored_pin_status);
						} else if (auth_operation_type == "VALIDATEFINGERPRINT") {
							fingerprintAuthentication(state_id, stored_pin_status);
						} else if (auth_operation_type == "DEREGISTERFINGERPRINT") {
							fingerprintUnenrol(state_id, stored_pin_status, "PIN");
						} else if (auth_operation_type == "LOGOUT") {
							logout(state_id);
						} else {
							trace("error", methodName, "DI002","CI002");
						}
					}
				} else {
					trace("error", methodName, "DI003","CI002");
				}
			} catch (e) {
				trace("info", methodName, "An error occured with the security flow: " + e.message);
				handleError(e.message);
			}
		}
	} else if (request_type == "resource") {
		trace("info", methodName, "Determined the request is resource request. This is an existing device making a request to a protected resource.");
		resourceFlow(state_id);
	} else if (request_type == "session") {
		trace("info", methodName, "Determined the request is session request. Exchange request accesstoken to web session");
		sessionFlow(state_id);
	} else {
		trace("error", methodName, "DI004","CI002");
	}
	trace("exit", methodName);
}



	main_fp_pin_flow();
