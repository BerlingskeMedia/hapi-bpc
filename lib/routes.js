/*jshint node: true */
'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');


const authorize_validation = Joi.object().keys({
  UID: Joi.string(),
  UIDSignature: Joi.string(),
  signatureTimestamp: Joi.string(),
  ID: Joi.any().strip(),
  id_token: Joi.string(),
  access_token: Joi.string(),
  rsvp: Joi.string()
})
.oxor('UID', 'id_token', 'rsvp') // oxor: Defines an exclusive relationship between a set of keys where only one is allowed but none are required.
.with('UID', ['UIDSignature', 'signatureTimestamp'])
.with('id_token', ['access_token']);


const ticket_validation = Joi.object().keys({
  id: Joi.string(),
  key: Joi.string(),
  algorithm: Joi.string().allow('sha1', 'sha256').default('sha256'),
  app: Joi.string(),
  grant: Joi.string(),
  user: Joi.string(),
  exp: Joi.number(),
  scope: Joi.array().items(Joi.string())
})
.with('id', ['key', 'algorithm', 'app', 'grant', 'user', 'exp', 'scope']);

function returnJSON(str) {
  try {
    return JSON.parse(str);
  } catch (e) {
    return str;
  }
}

const routes = [
  {
    method: 'POST',
    path: '/authenticate',
    options: {
      cors: false,
      auth: false,
      state: {
        parse: true,
        failAction: 'log'
      },
      validate: {
        payload: Joi.alternatives().try(authorize_validation, ticket_validation)
      }
    },
    handler: async function (request, h) {
      return authorize(request.payload, request, h);
    }
  },
  {
    method: 'POST',
    path: '/authorize',
    options: {
      cors: false,
      auth: false,
      state: {
        parse: true,
        failAction: 'log'
      }
    },
    handler: async function (request, h) {
      const schema = Joi.alternatives().try(authorize_validation, ticket_validation);
      const validation = schema.validate(returnJSON(request.payload));
      if (validation.error) {
        throw validation.error;
      }
      return authorize(request.payload, request, h);
    }
  },
  {
    method: 'GET',
    path: '/authenticate',
    options: {
      cors: false,
      auth: false,
      state: {
        parse: true,
        failAction: 'log'
      },
      validate: {
        query: authorize_validation
      }
    },
    handler: async function (request, h) {
      return authorize(request.query, request, h);
    }
  },
  {
    method: 'GET',
    path: '/authorize',
    options: {
      cors: false,
      auth: false,
      state: {
        parse: true,
        failAction: 'log'
      },
      validate: {
        query: authorize_validation
      }
    },
    handler: async function (request, h) {
      return authorize(request.query, request, h);
    }
  },
  {
    method: 'DELETE',
    path: '/authenticate',
    options: {
      cors: false,
      auth: false,
      state: {
        parse: true,
        failAction: 'log'
      }
    },
    handler: async function (request, h) {
      const bpc = h.bpc;

      // Deleting ticket from cookies.
      // This is not a global signout.
      h.unstate(bpc.env.state_name);

      return h.response({ status: 'ok' });
    }
  },
  {
    method: 'DELETE',
    path: '/authorize',
    options: {
      cors: false,
      auth: false,
      state: {
        parse: true,
        failAction: 'log'
      }
    },
    handler: async function (request, h) {
      const bpc = h.bpc;

      // Deleting ticket from cookies.
      // This is not a global signout.
      h.unstate(bpc.env.state_name);

      return h.response({ status: 'ok' });
    }
  }
];


module.exports = routes;


async function authorize(data, request, h) {

  const bpc = h.bpc;

  const oldTicket = request.state[bpc.env.state_name] || (( data.id && data.key) ? data : null);

  let ticket;

  // If this a new lognon
  if (data.rsvp || data.id_token || data.UID) {
    let rsvp = Object.assign({}, data);

    // Getting new RSVP
    if(data.id_token || data.UID) {

      const payload = Object.assign({}, data, { app: bpc.env.app });
      delete payload.returnUrl;

      rsvp = await bpc.request(
        {
          path: '/rsvp',
          method: 'POST',
          payload: payload
        }
      );
    }

    ticket = await bpc.request(
      {
        path: '/ticket/user',
        method: 'POST',
        payload: rsvp
      }
    );

  } else if (oldTicket) {

    ticket = await bpc.request(
      {
        path: '/ticket/reissue',
        method: 'POST'
      },
      oldTicket
    );

  } else {

    throw Boom.unauthorized();

  }

  h.state(bpc.env.state_name, ticket);

  return h.response(ticket);
}
