/*jshint node: true */
'use strict';

const Boom = require('boom');

const scheme = function (server, options) {

    return {

        authenticate: async function (request, h) {

            const bpc = request.server.services().bpc;

            const ticket = request.state[bpc.env.state_name];
            const authorization = request.headers.authorization;

            if (ticket) {

                await bpc.request({
                    path: '/validate',
                    method: 'GET',
                },
                ticket);

                return h.authenticated({ credentials: ticket });

            } else if (authorization) {

                const credentials = await bpc.request({
                    path: '/validate',
                    method: 'POST',
                    payload: {
                        authorization: request.headers.authorization
                    }
                },
                'appTicket');
    
                return h.authenticated({ credentials: credentials });

            } else {

                throw Boom.unauthorized(null, 'bpc');

            }
        }
    };
};

module.exports = scheme;
