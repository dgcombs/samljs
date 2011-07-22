/*
** Many Thanks to O'Reilly Hacks
** http://oreilly.com/hacks/
** http://oreilly.com/pub/h/2127
*/

// XML writer with attributes and smart attribute quote escaping 
function element(name,content,attributes){
	var att_str = '';
	if (attributes) { // tests false if this arg is missing!
		att_str = formatAttributes(attributes)
	}
	var xml;
	if (!content) {
		xml='<' + name + att_str + '/>'
	}
	else {
		xml='<' + name + att_str + '>' + content + '</'+name+'>'
	}
	return xml
}

var	APOS = "\'"
	, QUOTE = '\"'
	, ESCAPED_QUOTE = {};
	ESCAPED_QUOTE[2] = '&quot;';
	ESCAPED_QUOTE[APOS] = '&apos;';
   
/*
   Format a dictionary of attributes into a string suitable
   for inserting into the start tag of an element.  Be smart
   about escaping embedded quotes in the attribute values.
*/
function formatAttributes(attributes) {
	var att_value
	, apos_pos, quot_pos
	, use_quote, escape, quote_to_escape
	, att_str
	, re
	, result = '';
   
	for (var att in attributes) {
		att_value = attributes[att]
        
		// Find first quote marks if any
		apos_pos = att_value.indexOf(APOS)
		quot_pos = att_value.indexOf(QUOTE)
       
		// Determine which quote type to use around 
		// the attribute value
		if (apos_pos == -1 && quot_pos == -1) {
			att_str = ' ' + att + "='" + att_value +  "'";
			result += att_str;
			continue
		}
        
		// Prefer the single quote unless forced to use double
		if (quot_pos != -1 && quot_pos < apos_pos) {
			use_quote = APOS;
		} else {
			use_quote = QUOTE;
		}
   
		// Figure out which kind of quote to escape
		// Use nice dictionary instead of yucky if-else nests
		escape = ESCAPED_QUOTE[use_quote];
        
		// Escape only the right kind of quote
		re = new RegExp(use_quote,'g');
		att_str = ' ' + att + '=' + use_quote + 
			att_value.replace(re, escape) + use_quote;
		result += att_str;
	}
	return result
}

function createSAML() {
	// Create the SAML expression using features from the SAMLForm
	// first, get the current date/time and expiration date/time for this assertion
	var d = new Date();
	var thisInstant=d.getFullYear() + "-" + (d.getMonth()+1) + "-" + d.getDate() + "T" + d.getHours() + ":" + d.getMinutes() + ":00Z";
	d.setMinutes(d.getMinutes() + 10);
	var nextInstant=d.getFullYear() + "-" + (d.getMonth()+1) + "-" + d.getDate() + "T" + d.getHours() + ":" + d.getMinutes() + ":00Z";
	
	// set the Assertion Information
	// Set Assertion ID parameter to form's assertionID
	var assertionID = document.SAMLForm.assertionID.value;
	var xmlSubject = element("saml:Subject",element("saml:NameID",document.SAMLForm.subjectID.value,{"Format":"urn:oasis:names:tc:SAML1.1:nameid-format:emailAddress","Version":"2.0","IssueInstant":thisInstant}));
	var xmlIssuer = element("saml:Issuer",document.SAMLForm.IssuerID.value,{"Format":"urn:oasis:names:tc:SAML:2.0:nameid-format:entity"});
	var xmlConditions = element("saml:Conditions","",{"NotBefore":thisInstant,"NotOnOrAfter":nextInstant});
	var xmlAuthnContext = element("saml:AuthnContext",element("saml:AuthnContextClassRef","urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",{}),{});
	var xmlAuthnStatement = element("saml:AuthnStatement",xmlAuthnContext,{"AuthnInstant":thisInstant,"SessionIndex":"Some Big Number"});
	var xmlAssertion = element("saml:Assertion",xmlSubject + xmlIssuer + xmlConditions + xmlAuthnStatement,{"xmlns:saml":"urn:oasis:names:tc:SAML:2.0:assertion","ID":document.SAMLForm.assertionID.value,"Version":"2.0"});
	var xmlResponse = element("samlp:Response",xmlAssertion,{"xmlns:samlp":"urn:oasis:names:tc:SAL:2.0:protocol","ID":"Some Big Number","IssueInstant":thisInstant,"Version":"2.0"});
	return xmlResponse;
}

function submit_form() {
	// set Action for URL
	//document.SAMLForm.action=document.SAMLFormat.targetID.value;
	//document.SAMLForm.action="https://fedwb01i.hughestelematics.com/local/pnr.cgi";
	document.SAMLForm.action="https://fedwb01i.hughestelematics.com/local/pnr.cgi";
	var SAMLResponse = createSAML();
	alert(SAMLResponse);
	var myIV = "";
	var key="JpKJLO2qaMkgEs4VFYEX+eYnn0J6LXXI";
	SAMLResponse=des (key, SAMLResponse, true, 1, myIV, 0)
	SAMLResponse=Base64.encode(SAMLResponse);
	alert(SAMLResponse);
	document.SAMLForm.SAMLResponse.value=SAMLResponse;
	document.SAMLForm.submit();
	//window.close();
}