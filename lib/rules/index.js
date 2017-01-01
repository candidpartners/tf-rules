'use strict';
const fs = require('fs');
const debug = require('debug')('tfrules/rule-loader');

const rules = {};

const files = fs.readdirSync( __dirname );

for( let file of files ) {
  if( file != 'index.js' && file.endsWith( '.js' ) && ! file.endsWith( '.spec.js' ) && ! file.endsWith( '.component.js') ) {
    debug( 'Loading %s', file );
    rules[ file.slice( 0, -3 ) ] = require( `${__dirname}/${file}` );
  }
}

module.exports = rules;
