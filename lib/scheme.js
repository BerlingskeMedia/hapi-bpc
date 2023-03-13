/*jshint node: true */
'use strict';

const Boom = require('@hapi/boom');

const scheme = function (server, options) {
    return {
        authenticate: async function (request, h) {
            const bpc = h.bpc;

            const ticket = request.state[bpc.env.state_name];
            const authorization = request.headers.authorization;
            try {
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
                    });

                    return h.authenticated({ credentials: credentials });

                } else {
                    throw Boom.unauthorized(null, 'bpc');
                }
            } catch (e) {
                throw Boom.unauthorized(null, 'bpc');
            }
        }
    };
};

module.exports = scheme;
