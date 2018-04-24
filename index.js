"use strict;"

/*
    CMU Shibboleth Passport Authentication Module

    This module exposes a passport Strategy object that is pre-configured to
    work with the CMU's Shibboleth identity provider (IdP). To use this, you 
    must register your server with the CMU IdP, and you can use the 
    metadataRoute() method below to provide the metadata necessary for 
    registration via the standard metadata url (urls.metadata).

    author: Dave Stearns

    Modified for use at Carnegie Mellon University by Artur Zayats
*/

//const passport = require('passport');
const saml = require('passport-saml');
const util = require('util');

const idPCert = 'MIIDLDCCAhSgAwIBAgIJAO1Zt6Sg0xhmMA0GCSqGSIb3DQEBBQUAMBgxFjAUBgNVBAMTDWxvZ2luLmNtdS5lZHUwHhcNMTQwMTIyMTkzMDM2WhcNMzAwNjI5MTkzMDM2WjAYMRYwFAYDVQQDEw1sb2dpbi5jbXUuZWR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4yIV5lVs9/7jdmRTi23AINTzGQTrL+p8EXmV1iL48YAZ36T+xnDpTXt2RDaioI34/P9vHYpSKY6C5gDNyXGQZYTrgJQHQRgJAGTsXshYoDeBboZZ9ax+7m86rKqmHZAprHALONubY0UtPDEGQKdMeeetAUAOh8kIKpGvKp96I+4pIT6S/p5VtBB80veOK6woqbzU0Qr9q1FbcZfJ6AjG8as9lBa9Si6vc/fGvFrjsJL3+cpvECuyG/yHp9obdwXLgxlQNPtXNeBgclgiaJJE8zWcZBUxWPboVeuC2Jfv7spIOcCyKPKTGUlobBoANGHqGMqbK+/7YzQ+J/s/4n0tvwIDAQABo3kwdzAdBgNVHQ4EFgQUoZye8kn1Hznd+tCaxJ3elowNIbYwSAYDVR0jBEEwP4AUoZye8kn1Hznd+tCaxJ3elowNIbahHKQaMBgxFjAUBgNVBAMTDWxvZ2luLmNtdS5lZHWCCQDtWbekoNMYZjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQCp51hb/WPVfRtdQNZm6OQj8I6HwDGWmu5PzUycJAkD/VYd3wCM1zLwd32LMbxbA2ArKWBstErEsUog94zvMBWyAeT3Q5Gyghji0emF0nbZpNjPjE9bXavMbUppXF2/VHbuBtzEMBxIKV53X2et2MMc9mnNzZN1rofuIB//W9Fg9IWV5PLVbsvEYI98IkJ5t4JP92/V5p497O8jMj6oLhy7mI4FNx0pQnirAvrQxxgFTwVV5SEm87DBYRblUb4ba0yYVSBQg0EVbIb7QEDxHFWbzt4+NLolAQAMSQW+SJKf9V7+6+4uhMwpJxQwezzn41u9kGTIg9F8/s0IrgsTlAm3';
//"https://login.cmu.edu/idp/profile/SAML2/Redirect/SSO"

//const idPEntryPoint = 'https://login.cmu.edu/idp/shibboleth';
const idPEntryPoint = 'https://login.cmu.edu/idp/profile/SAML2/Redirect/SSO';

//standard login, callback, logout, and meta-data URLs
//these will be exposed from module.exports so that
//clients can refer to them
//the metadata one in particular is important to get right
//as the auto-regisration process requires that exact URL
const urls = {
    metadata: '/Shibboleth.sso/Metadata',
    logoutUrl: 'https://s3.as.cmu.edu/Shibboleth.sso/Logout'
};

//export the urls map
module.exports.urls = urls;

//map of possible profile attributes and what name
//we should give them on the resulting user object
//add to this with other attrs if you request them
const profileAttrs = {
    'urn:oid:0.9.2342.19200300.100.1.3': 'email',
    'urn:oid:2.5.4.4': 'lastname',
    'urn:oid:2.5.4.42': 'firstname',

    'urn:oid:2.5.4.3': 'sn',
    'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',

    'urn:oid:1.3.6.1.4.1.5923.1.1.1.9': 'eduPersonScopedAffiliation',
    'urn:oid:0.9.2342.19200300.100.1.1': 'netId',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'affiliation',
    'urn:oid:2.16.840.1.113730.3.1.3': 'empNum',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'principalName',
    'urn:oid:2.5.4.18': 'box',
    'urn:oid:2.5.4.20': 'phone',
    'urn:oid:2.5.4.12': 'title',
    'urn:oid:1.2.840.113994.200.21': 'studentId',
    'urn:oid:1.2.840.113994.200.24': 'regId',
    'urn:oid:0.9.2342.19200300.100.1.1': 'Shib-uid',
    'urn:oid:0.9.2342.19200300.100.1.3': 'Shib-mail',
    'urn:oid:1.3.6.1.4.1.5643.10.0.1': 'Shib-uaId'
};



/*
    Passport Strategy for CMU Shibboleth Authentication
    This class extends passport-saml's Strategy, providing the necessary 
    options and handling the conversion of the returned profile into a 
    sensible user object.

    options should contain:
        entityId: your server's entity id,
        domain: your server's domain name,
        callbackUrl: login callback url (relative to domain),
        privateKey: your private key for signing requests (optional)
*/
function Strategy(options, verify) {

    var self = this;

    samlOptions = {
        entryPoint: idPEntryPoint,
        cert: idPCert,
        identifierFormat: null,
        issuer: options.entityId || options.domain,
        path: options.callbackUrl,
        callbackUrl: 'https://' + options.domain + options.callbackUrl,
        decryptionPvk: options.decryptionPvk || options.privateKey,
        privateCert: options.privateCert || options.privateKey,
        acceptedClockSkewMs: 180000,
        passReqToCallback: true
    };
    
    function formatProfile(req, profile){
       console.log("Format Profile");
       console.log(req);
       console.log(profile);
       return profile;  
    };

    function _verify(req, profile, done) {

      if (!profile)
        return done(new Error('Empty SAML profile returned!'));
      else
        profile = formatProfile(req, profile);

      if (!verify) return done(null, profile);

      if (options.passReqToCallback) {
        verify(req, profile, done);
      } else {
        verify(profile, done);
      }
    }

    saml.Strategy.call(this, samlOptions, _verify);

    this.name = options.name || 'cmushib';
}

util.inherits(Strategy, saml.Strategy);

//expose the Strategy
module.exports.Strategy = Strategy;

/*
    Route implementation for the standard Shibboleth metadata route
    usage:
        var uwshib = require(...);
        var strategy = new uwshib.Strategy({...});
        app.get(uwshib.urls.metadata, uwshib.metadataRoute(strategy, myPublicCert));
*/
module.exports.metadataRoute = function(strategy, publicCert) {
    return function(req, res) {
        res.type('application/samlmetadata+xml');
        res.status(200).send(strategy.generateServiceProviderMetadata(publicCert));
    }
} //metadataRoute

/*
    Middleware for ensuring that the user has authenticated.
    You can use this in two different ways. If you pass this to
    app.use(), it will secure all routes added after that.
    Or you can use it selectively on routes that require authentication
    like so:
        app.get('/foo/bar', ensureAuth(loginUrl), function(req, res) {
            //route implementation
        });

    where loginUrl is the url to your login route where you call
    passport.authenticate()
*/
module.exports.ensureAuth = function(loginUrl) {
    return function(req, res, next) {
        if (req.isAuthenticated())
            return next();
        else {
            req.session.authRedirectUrl = req.url;
            res.redirect(loginUrl);            
        }
    }
};

/*
    Middleware for redirecting back to the originally requested URL after
    a successful authentication. The ensureAuth() middleware above will
    capture the current URL in session state, and when your callback route
    is called, you can use this to get back to the originally-requested URL.
    usage:
        var uwshib = require(...);
        var strategy = new uwshib.Strategy({...});
        app.get('/login', passport.authenticate(strategy.name));
        app.post('/login/callback', passport.authenticate(strategy.name), uwshib.backtoUrl());
        app.use(uwshib.ensureAuth('/login'));
*/
module.exports.backToUrl = function(defaultUrl) {
    return function(req, res) {
        var url = req.session.authRedirectUrl;
        delete req.session.authRedirectUrl;
        res.redirect(url || defaultUrl || '/');
    }
};

