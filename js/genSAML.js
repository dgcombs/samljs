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
	, ESCAPED_QUOTE = {}
	//, ESCAPED_QUOTE[QUOTE] = '&quot;'
	//, ESCAPED_QUOTE[APOS] = '&apos;';
   
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


/*
** SAML Format
** root XML
** samlp:RESPONSE
** saml:Issuer
** samlp:Status -- samlp:StatusCode
** saml:Assertion
** saml:Issuer
** saml:Subject -- saml:NameID -- saml:SubjectConfirmation -- saml:SubjectConfirmationData
** saml:Conditions
*/
function appendNode(Document, nodeName) {
	var link = Document.createElement(nodeName);
	return link;
	}

// Append Node -- append a node at the bottom
// Insert Node -- Insert a node at the pointer
// Set node value -- i.e. <node>Parameter</node>
// Set node parameter -- i.e. <node parameter = "this is a test"/>

function submit_form() {
	//alert(samlTemplate);
	//Set Action URL, set TCID number and Assertion number
	var xmlDoc = element("saml:Assertion","this is an assertion value", {"saml":"assertion"});
	//var xmlDoc = mkXML(SAMLtemplate)
	//var assertion = xmlDoc.createElement("saml:Assertion");
	//assertion.setAttribute('Version', '2.0');
	//xmlDoc.getElementById("dan").appendChild(assertion);
	//xmlDoc.childNode[0].insertBefore(assertion);
	alert(xmlDoc);
	//alert(document.SAMLForm.SAMLResponse.value);
	//document.SAMLForm.submit();
	//var createData = { "url":"http://www.novell.com"};
	//chrome.tabs.create({"url":"http://www.novell.com"});
	//window.close();
}