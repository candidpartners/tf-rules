'use strict';
const fs = require('fs');
const path = require('path');
const debug = require('debug')('snitch/rule-loader');

const rules = {};

function walk(dir) {
    let results = [];
    let list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = dir + '/' + file;
        let stat = fs.statSync(file);
        if (stat && stat.isDirectory()) results = results.concat(walk(file));
        else results.push(file)
    });
    return results
}

const files = walk(__dirname)
    .map(x => x.replace(__dirname + "/",""))

for( let file of files ) {
  if( file != 'index.js' && file.endsWith( '.js' ) && ! file.endsWith( '.spec.js' ) && ! file.endsWith( '.component.js') ) {
    debug( 'Loading %s', file );
    let getName = (filePath) => path.basename(filePath).slice(0,-3);
    try{
        rules[ getName(file) ] = require( `${__dirname}/${file}` );
    } catch( err){
        throw err;
    }
  }
}

module.exports = rules;
