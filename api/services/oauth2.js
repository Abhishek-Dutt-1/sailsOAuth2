var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var BearerStrategy= require('passport-http-bearer').Strategy;

// Client Login handler
passport.use( 'client-basic', new BasicStrategy( function(clientName, password, callback) {
    Client.findOne({name: clientName}, function(err, client) {
        if(err) { return callback(err); }

        // Client not found or password incorrect
        if(!client || client.secret != password) { return callback(null, false); }

        // Client found
        return callback(null, client);
    });
}));

// Token Auth handler
passport.use(new BearerStrategy( function(accessToken, callback) {
    AccessToken.findOne( {token: accessToken}, function(err, token) {
        if(err) { return callback(err); }

        // No token found
        if(!token) { return callback(null, false); }

        User.findOne( {id: token.userId}, function(err, user) {
            if(err) { return callback(err); }

            // No user found
            if(!user) { return callback(null, false); }

            // TODO: decide where to store scope
            callback( null, user, { scope: '*' } );
        });
    });
}));
