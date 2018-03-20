This is a fork of [ssh-keygen](https://github.com/ericvicenti/ssh-keygen) NPM module, which adds support for signing (certification) of an existing public key by a specified CA key.

In order to provide this functionality, the following parameters have been added:
 * sign, sets the module to keysign'ing mode
 * cakey, location of existing SSH CA key. Required when sign parameter is true
 * publickey, location of public key to be signed. Required when sign parameter is true
 * identity, Required when sign parameter is true
 * principal, Optional principal name (user or host name) to be included in certificate
 * validity, Optional validity interval for certificate.  Should match accepted format of ssh-keygen's -V flag. Please see -V entry of ssh-keygen man page for more information.
