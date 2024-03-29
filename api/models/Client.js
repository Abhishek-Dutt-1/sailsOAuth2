/**
* Client.js
*
* @description :: TODO: You might write a short summary of how this model works and what it represents here.
* @docs        :: http://sailsjs.org/#!documentation/models
*/

module.exports = {

    attributes: {
        name: {
            type: 'string',
            required: true,
            unique: true
        },
/*
 * Client id is implicitly provided by Sails
        id: {
            type: 'string',
            required: true
        },
*/
        secret: {
            type: 'string',
            required: true
        },
        userId: {
            type: 'string',
            required: true
        }
    }

};

