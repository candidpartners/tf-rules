'use strict';
const fs = require('fs');

const rules = {};

const files = fs.readdirSync( __dirname );

for( let file of files ) {
  if( file != 'index.js' && file.endsWith( '.js' ) && ! file.endsWith( '.spec.js' ) && ! file.endsWith( '.component.js') ) {
    rules[ file.slice( 0, -3 ) ] = require( `${__dirname}/${file}` );
  }
}

module.exports = rules;
