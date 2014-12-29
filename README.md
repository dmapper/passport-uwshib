Passport-CMUShib
===============

Passport authentication strategy that works with the Carnegie Mellon University's Shibboleth single-sign on service. This uses the fabulous [passport-saml](https://github.com/bergie/passport-saml) module for all the heavy lifting, but sets all the default options so that it works properly with the CMU Shibboleth Identity Provider (IdP).

Note that in order to use the CMU IdP for authentication, **you must [register your server](http://www.cmu.edu/computing/web/authenticate/web-login/shib.html)**. 

Installation
------------
    npm install passport-cmushib

or if using a [package.json file](https://www.npmjs.org/doc/package.json.html), add this line to your dependencies hash:

    "passport-cmushib": "*"

and do an `npm install` or `npm update` to get the most current version.

Usage
-----
There is a fully-working example server script in [/example/server.js](https://github.com/dmapper/passport-cmushib/blob/master/example/server.js), and an associated [package.json](ttps://github.com/dmapper/passport-cmushib/blob/master/example/package.json), which you can use to install all the necessary packages to make the example script run (express, express middleware, passport, etc.). Refer to that as I explain what it is doing.

This module provides a Strategy for the [Passport](http://passportjs.org/) framework, which is typically used with [Express](http://expressjs.com/). Thus, there are several modules you need to require in your server script in addition to this module.

    var http = require('http');                     //http server
    var https = require('https');                   //https server
    var fs = require('fs');                         //file system
    var express = require("express");               //express middleware
    var morgan = require('morgan');                 //logger for express
    var bodyParser = require('body-parser');        //body parsing middleware
    var cookieParser = require('cookie-parser');    //cookie parsing middleware
    var session = require('express-session');       //express session management
    var passport = require('passport');             //authentication middleware
    var cmushib = require('passport-cmushib');      //CMU Shibboleth auth strategy

The example script then gets the server's domain name from an environment variable. This allows you to run the example script without modification. Simply export a value for `DOMAIN` and run the script.

    export DOMAIN=idecisiongames.com
    node server.js

You can also override the default HTTP and HTTPS ports if you wish by specifying `HTTPPORT` and `HTTPSPORT` environment variables.

The example script then loads a public certificate and associated private key from two files in a `/security` subdirectory.

    var publicCert = fs.readFileSync('./security/server-cert.pem', 'utf-8');
    var privateKey = fs.readFileSync('./security/server-pvk.pem', 'utf-8');

These are used not only for the HTTPS server, but also to sign requests sent to the CMU IdP. You can use [openssl](http://www.sslshopper.com/article-most-common-openssl-commands.html) to generate keys and certificate signing requests. The CMU IdP seems to require that your server responds to HTTPS requests, so you should get a signed certificate for your server before trying to register it.

The script continues by creating a typical Express application and registering the typical middleware. For more information on this, see the [Passport.js site](http://passportjs.org/).

Then the script creates the CMU Shibboleth Strategy, and tells Passport to use it.

    //create the CMU Shibboleth Strategy and tell Passport to use it
    var strategy = new cmushib.Strategy({
        entityId: domain,
        privateKey: privateKey,
        callbackUrl: loginCallbackUrl,
        domain: domain
    });

    passport.use(strategy);

The name of the strategy is `'cmusaml'`, but you can use the `.name` property of the Strategy to refer to that.

You will typically want to use sessions to allow users to authenticate only once per-sesion. The next functions are called by Passport to serialize and deserialize the user to the session. As noted in the comments, you would typically want to serialize only the unique ID (`.netID`) and reconstitute the user from your database during deserialzie. But to keep things simple, the script serializes the entire user and deserializes it again.

    passport.serializeUser(function(user, done){
        done(null, user);
    });

    passport.deserializeUser(function(user, done){
        done(null, user);
    });

Next, the script registers a few routes to handle login, the login callback, and the standard metadata. This module provides implementations for the metadata route, and you use passport.authenticate for the login and login callback routes. The login route will redirect the user to the CMU single sign-on page, and the CMU IdP will then redirect the user back to the login callback route.

    app.get(loginUrl, passport.authenticate(strategy.name), cmushib.backToUrl());
    app.post(loginCallbackUrl, passport.authenticate(strategy.name), cmushib.backToUrl());
    app.get(cmushib.urls.metadata, cmushib.metadataRoute(strategy, publicCert));

The `cmushib.backToUrl()` is a convenience middleware that will redirect the browser back to the URL that was originally requested before authentication.

Lastly, the script tells Express to use the `ensureAuth()` middleware provided by this module to secure all routes declared after this.

    //secure all routes following this
    app.use(cmushib.ensureAuth(loginUrl));

Any route requested after this middleware will require authentication. When requested, those routes will automatically redirect to the `loginUrl` if the user has not already authenticated. After successful authentication, the browser will be redirected back to the original URL, and the user information will be available via the `.user` property on the request object.

Note that `ensureAuth` can also be used to selectively secure routes. For example:

    app.get('protected/resource', ensureAuth(loginUrl), function(req, res) {
        //user has authenticated, do normal route processing
        //user is available via req.user
    });
