var passport = require('passport');
var oauth2orize = require('oauth2orize');

var server = oauth2orize.createServer();

// Session serializing and deserializing functions
server.serializeClient( function(client, callback) {
    return callback(null, client._id);
});
server.deserializeClient( function(id, callback) {
    Client.findOne( { _id: id }, function(err, client) {
        if(err) { return callback(err); }
        return callback(null, client);
    });
});

// Generate a new Authrorization Code for a given Client
server.grant(oauth2orize.grant.code( function(client, redirectUri, user, ares, callback) {

    // Create a new Authrorizaiton Code
    AuthorizationCode.create( {
        clientId: client.id,
        redirectUri: redirectUri,
//        scope: ares.scope,
        userId: user.id,
        code: uid(16)
    }).exec( function(err, newAuthCode) {
        if(err) { return callback(err, null); }
        return callback(null, newAuthCode.code);
    });
}));

// Function to exchange Authorization Code for a Access Token
server.exchange(oauth2orize.exchange.code( function(client, authCode, redirectUri, callback) {

    AuthrorizationCode.findOne({
        code: authCode
    }).exec( function(err, foundAuthCode) {
        if(err) { return callback(err); }
        if(foundAuthCode === undefined) { return callback(null, false); }
        // Authorization Code found but it is registered with some other client
        if(client.clientId != foundAuthCode.clientId) {
            return callback(null, false);
        }

        // Authorization Code found, is registered to the correct Client but
        // the client is asking for a different redirectUri 
        if( redirectUri != foundAuthCode.redirectUri ) {
            return callback(null, false);
        }
        
        // Delete the Authrorization Code now since it has been used
        AuthorizationCode.destroy({
            code: authCode
        }).exec( function(err) {
            return callback(null, false);
        });
        
        // Create a new Access Token
        AccessToken.create( {
            token: uid(256),
            clientId: authCode.clientId,
//            scope. authCode.scope,
            userId: authCode.userId
        }).exec( function(err, token) {
            if(err) { return callback(err); }
            callback(null, token);
        });

    });
}));

module.exports = {
    http: {
        customMiddleware: function(app) {

            console.log( 'Express middleware for passport' );
            app.use( passport.initialize() );
            app.use( passport.session() );

            // OAuth2orize routes
            app.get('api/oauth/authorize', 
//                    login.ensureLoggedIn(), 
                    server.authorize( function(clientId, redirectUri, callback) {
                        Client.findOne({id: clientId}, function(err, client) {
                            if(err) { return callback(err); }
                            if(!client) { return callback(null, false); }
                            if(client.redirectUri != redirectUri) { return callback(null, false); }
                            return callback(null, client, client.redirectUri);
                        });
                    }),
                    server.errorHandler(),
                    function(req, res) {
                        res.render('dialog', {
                            transactionID: req.oauth2.transactionID,
                            user: req.user,
                            client: req.oauth2.client
                        });
                    }
            );

            app.post( 'api/oauth/decision', 
//                    login.ensureLoggedIn(), 
                    server.decision() 
            );

            app.post( 
                'api/oauth/token', 
//                trustedClientPolicy, 
                passport.authenticate(['basic', 'oauth2-client-password'], 
                    {session: false} ),
                server.token(),
                server.errorHandler()
            );

        }
    }
};
