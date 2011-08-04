/*
** Generate SAML
*/

/*
**
** SAML Assertion Format

* XML Declaration

*samlp:Response

**saml:Issuer

**samlp:Status

	***samlp:StatusCode

**saml:Assertion
***saml:Issuer
***saml:Subject
****saml:NameID
****saml:SubjectConfirmation
*****saml:SubjectConfirmationData
***saml:Conditions
****saml:AudienceRestriction
*****saml:Audience
***saml:AuthnStatement
****saml:AuthnContext
*****samlAuthnContextClassRef
***saml:AttributeStatement
****saml:Attribute
*****saml:AttributeValue
**
*/
var thisInstant;
var nextInstant;

function createIssuer() {
	// Create the XML expression for the Issuer section
	return element("saml:Issuer",document.SAMLForm.IssuerID.value,{"Format":"urn:oasis:names:tc:SAML:2.0:nameid-format:entity"});
}

function createStatus() {
}

function createSubject() {
	return element("saml:Subject",element("saml:NameID",document.SAMLForm.subjectID.value,{"Format":"urn:oasis:names:tc:SAML1.1:nameid-format:emailAddress","Version":"2.0","IssueInstant":thisInstant}));
}

function createAuthnContext() {
	return element("saml:AuthnContext",element("saml:AuthnContextClassRef","urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",{}),{});
}
	
function createAuthnStatement() {
	return element("saml:AuthnStatement",createAuthnContext(),{"AuthnInstant":thisInstant,"SessionIndex":"Some Big Number"});
}

function createConditions() {
	return element("saml:Conditions",createAudienceRestriction(),{"NotBefore":thisInstant,"NotOnOrAfter":nextInstant});
}

function createAssertion() {
	return element("saml:Assertion",createSubject() + createIssuer() + createConditions() + createAuthnStatement(),{"xmlns:saml":"urn:oasis:names:tc:SAML:2.0:assertion","ID":document.SAMLForm.assertionID.value,"Version":"2.0"});
}

function createSAML() {
	return element("samlp:Response",createAssertion(),{"xmlns:samlp":"urn:oasis:names:tc:SAL:2.0:protocol","ID":"Some Big Number","IssueInstant":thisInstant,"Version":"2.0"});
}

function submit_form() {
	// first, get the current date/time and expiration date/time for this assertion
	var d = new Date();
	var thisInstant=d.getFullYear() + "-" + (d.getMonth()+1) + "-" + d.getDate() + "T" + d.getHours() + ":" + d.getMinutes() + ":00Z";
	d.setMinutes(d.getMinutes() + 10);
	var nextInstant=d.getFullYear() + "-" + (d.getMonth()+1) + "-" + d.getDate() + "T" + d.getHours() + ":" + d.getMinutes() + ":00Z";
	// set Action for URL
	document.SAMLForm.action=document.SAMLForm.targetID.value;
	var SAMLResponse = createSAML();
	// alert(SAMLResponse);
	switch (document.SAMLForm.Encrypt.value) {
		case "DES":
			var myIV = "";
			var key="JpKJLO2qaMkgEs4VFYEX+eYnn0J6LXXI";
			var des = new DES(key,myIV);
			SAMLResponse=des.encrypt(SAMLResponse)
			SAMLResponse=Base64.encode(SAMLResponse);
			console.log("SAMLResponse is : " + SAMLResponse);
			document.SAMLForm.SAMLResponse.value=SAMLResponse;
			break;
		case "3DES":
			break;
		case "TEA":
			break;
		case "AES":
			break;
		default:
	}
	document.SAMLForm.SAMLResponse.value=SAMLResponse;
	document.SAMLForm.submit();
}