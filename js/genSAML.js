/*
** Generate SAML
*/

/*
**
** SAML 2.0 Assertion Format
** !!! Caution !!!
** The information below is my understanding of a SAML Assertion format:
** ---------------
** 1) the Response section - the primary container for idp communication to sp
**	Inside the Response are Issuer and Status and inside Status is Status Code
** 2) the Assertion Section contains the several key bits of information
**	The Issuer (again)
**	The Subject (including NameID, Subject Confirmation and Subject Confirmation Data)
**	The Conditions of the Assertion including Audience Restriction and Audience
**	The AuthnStatement with AuthnContext and AuthnContextClassRef
**	The AttributeStatement with Attribute and AttributeValue
** 3) the Signature section
**	Contains information about the security used to sign the Assertion
** (The code for this section is still pending)
**
**	The standard XML Declaration is not required/mandated
**	<?xml version="1.0" encoding="UTF-8"?>
** 
** Because of this hierarchy, the code below is written as a series of embeddable
** functions. No attempt at streamlining, optimization or execution is attempted.
** The goals include simplicity, clarity and accessiblity for those attempting to use
** this code to test SAML-based systems.
*/
var thisInstant;
var nextInstant;
var key="JpKJLO2qaMkgEs4VFYEX+eYnn0J6LXXI"; // a DES Key
//var key = ""; // another DES Key

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

function createAudienceRestriction() {
}

function createConditions() {
	return element("saml:Conditions",createAudienceRestriction(),{"NotBefore":thisInstant,"NotOnOrAfter":nextInstant});
}

function createAssertion() {
	/*
	** Based on the variable document.SAMLForm.Encrypt.value
	** Choose an encryption type for Assertion contents
	** <element name="EncryptedAssertion" type="saml:EncryptedElementType"/>
	*/
	var assertionContents = createSubject() + createIssuer() + createConditions() + createAuthnStatement();
	if (document.SAMLForm.encryptQ.value == "assertion") {
		switch (document.SAMLForm.Encrypt.value) {
			case "DES":
				var des = new DES(key, "");
				return element("saml:EncryptedAssertion",Base64.encode(des.encrypt(assertionContents)),{"xmlns:saml":"urn:oasis:names:tc:SAML:2.0:assertion","ID":document.SAMLForm.assertionID.value,"Version":"2.0"});
				break;
			case "AES":
			case "TEA":
			default:
				return element("saml:Assertion",assertionContents,{"xmlns:saml":"urn:oasis:names:tc:SAML:2.0:assertion","ID":document.SAMLForm.assertionID.value,"Version":"2.0"});
				break;
		}
	} else {
		return element("saml:Assertion",assertionContents,{"xmlns:saml":"urn:oasis:names:tc:SAML:2.0:assertion","ID":document.SAMLForm.assertionID.value,"Version":"2.0"});
	}
}

function createSAML() {
	if (document.SAMLForm.encryptQ.value == "response") {
		switch (document.SAMLForm.Encrypt.value) {
			case "DES":
				var des = new DES(key,"");
				return element("samlp:Response",Base64.encode(des.encrypt(createAssertion())),{"xmlns:samlp":"urn:oasis:names:tc:SAL:2.0:protocol","ID":"Some Big Number","IssueInstant":thisInstant,"Version":"2.0"});
				break;
			case "AES":
			case "TEA":
			default:
				return element("samlp:Response",createAssertion(),{"xmlns:samlp":"urn:oasis:names:tc:SAL:2.0:protocol","ID":"Some Big Number","IssueInstant":thisInstant,"Version":"2.0"});
				break;
		}
	} else {
		return element("samlp:Response",createAssertion(),{"xmlns:samlp":"urn:oasis:names:tc:SAL:2.0:protocol","ID":"Some Big Number","IssueInstant":thisInstant,"Version":"2.0"});
	}
}

function submit_form() {
	// first, get the current date/time and expiration date/time for this assertion
	var d = new Date();
	thisInstant=d.getFullYear() + "-" + (d.getMonth()+1) + "-" + d.getDate() + "T" + d.getHours() + ":" + d.getMinutes() + ":00Z";
	d.setMinutes(d.getMinutes() + 10);
	nextInstant=d.getFullYear() + "-" + (d.getMonth()+1) + "-" + d.getDate() + "T" + d.getHours() + ":" + d.getMinutes() + ":00Z";
	// set Action for URL
	document.SAMLForm.action=document.SAMLForm.targetID.value;
	key = document.SAMLForm.encryptionKey.value;
	document.SAMLForm.SAMLResponse.value = createSAML();
	document.SAMLForm.submit();
}