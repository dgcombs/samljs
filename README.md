# README for samljs.

The effort for this came from a miserable experience implementing non-standard federated identity.

The idP wrote their end in Java from scratch.
They created their metadata file using notepad.
We were never able to successfully synchronize signatures.

In order to test the systems we were putting in place,
I wrote SAMLjs.

It will take the place of an idP and generate a standard assertion and either
POST or SOAP it to the SP endpoint.

It helped me troubleshoot my pseudo-SP code.
Good luck with yours!