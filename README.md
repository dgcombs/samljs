# README for samljs.

The effort for this came from a miserable experience implementing non-standard federated identity using SAML 2.0

The idP wrote their end in Java from scratch. They created their metadata file using notepad. We were never able to successfully synchronize signatures with the Oracle Federation.

In order to test the systems we were putting in place, I wrote _SAMLjs_.

It will take the place of an idP and generate a standard assertion and either
POST it to the SP endpoint of your choice.

It helped me troubleshoot my pseudo-SP code.
Good luck with yours!