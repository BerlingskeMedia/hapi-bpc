/*jshint node: true */
'use strict';

const packageJson = require('../package.json');
const log = require('util').log;
const Url = require('url');
const Hawk = require('@hapi/hawk');

const bpc_client = require('bpc_client').default;

bpc_client.events.on('ready', () => {
    log('Connected to BPC on', bpc_client.url, 'AS', bpc_client.app.id);
})

const routes = require('./routes');
const scheme = require('./scheme');


const plugin = {
  name: packageJson.name,
  version: packageJson.version,
  async register(server, options) {

    server.auth.scheme('bpc', scheme);
    server.auth.strategy('bpc', 'bpc');

    let BPC_URL;

    try {
      BPC_URL = Url.parse(bpc_client.url);
    } catch (ex) {
      console.error('BPC URL is missing or invalid.');
      process.exit(1);
    }
    
    const env = Object.assign({}, BPC_URL, {
      app: bpc_client.app.id,
      state_name: `${ bpc_client.app.id }_ticket`
    });

    // Defaults cookie options. Can be overrriden using options.state
    const stateOptions = Object.assign({
      ttl: 1000 * 60 * 60 * 24 * 30 * 12, // (one year)
      isHttpOnly: true,
      isSecure: process.env.SECURE_COOKIE === 'false' ? false : true,
      isSameSite: 'Strict',
      path: '/',
      encoding: 'base64json'
    }, options.state);

    server.state(env.state_name, stateOptions);
    
    // Overrride cors rules using options.cors
    // Checking on "undefined" and "null" to support this: { cors: false }
    if(options.cors !== undefined && options.cors !== null) {
      routes.forEach((route => route.options.cors = options.cors));
    }

    server.route(routes);

    server.decorate('toolkit', 'bpc', { request: bpc_client.request, env });
    server.decorate('server', 'bpc', bpc_client);
    server.decorate('server', 'hawk', Hawk);

  }
};

module.exports = plugin;
