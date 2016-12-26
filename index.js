'use strict';
const debug     = require('debug')('tf-rules/index');
const _         = require('lodash');
const fs        = require('fs');
const co        = require('co');
const Ajv       = require('ajv');
const colors    = require('colors');
const jp        = require('jmespath');

const symbols   = require('./lib/reporters/symbols');

const ajv = new Ajv(); 

function validateConfig( rules, config ) {
  return _.reduce( config, ( accum, value, key ) => {
    if( rules[ key ] == undefined ) {
      accum.push( { severity : 'warning', message : `${key} rule not available in this version` } );
    } else if ( ! ajv.validate( rules[ key ].schema || {}, value ) ) {
      accum.push( { severity : 'error', message : `${key} configuration invalid`, details : ajv.errors } );
    }
    return accum;
  }, [] );
}

function report( result, instanceName, rule ) {
  if( result.valid == 'success' ) {
    console.log( colors.green( symbols.ok ), " ", colors.gray( rule.docs.description ), instanceName );
  } else if( result.valid == 'fail' ) {
    console.log( colors.red( symbols.err ), " ", colors.gray( rule.docs.description ), instanceName );
  }
}

function *validatePlan( rules, allConfig, plan ) {
  debug( 'allConfig: %O', allConfig );
  let results = [];
  for( let ruleKey of _.keys( rules ) ) {
    debug( 'ruleKey: %s', ruleKey );
    let config = allConfig[ ruleKey ];
    let rule = rules[ ruleKey ];
    let paths = rule.paths;
    let searchResults = _.keys( paths ).map( path => ({
      rule    : ruleKey,
      path    : {
        name  : path,
        query : paths[ path ]
      },
      search  : jp.search( plan, paths[ path ] )
    }));
    for( let searchResult of searchResults ) {
      if( _.isObject( searchResult.search ) && ! _.isArray( searchResult.search ) ) {
        for( let instanceName of _.keys( searchResult.search ) ) {
          let instance = searchResult.search[ instanceName ];
          let result = yield rule.validate({ config, instance, plan, jp });
          results.push( result );
          report( result, instanceName, rule );
        }
      }
    }
  }
  return results;
}


module.exports = {
  validateConfig,
  validatePlan
};

