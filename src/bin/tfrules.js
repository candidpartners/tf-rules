'use strict';
const co      = require('co');
const cli     = require('./cli');
const debug   = require('debug')('tfrules/bin/tfrules');

debug( 'Startup calling cli.main' );
co( cli.main ).catch( cli.handleError ).then( cli.handleSuccess );

