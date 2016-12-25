'use strict';
const _         = require('lodash');
const fs        = require('fs');
const co        = require('co');
const Plan      = require('tf-parse').Plan;
const nconf     = require('nconf');
const Ajv       = require('ajv');
const colors    = require('colors');
const jp        = require('jmespath');

const ajv = new Ajv(); 

nconf.argv()
.env()
.file({
  file: '.tfrulesrc',
  format: require('nconf-yaml')
});

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

function *validatePlan( rules, allConfig, plan ) {
  for( let ruleKey of _.keys( rules ) ) {
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
          yield rule.validate({ config, instance, plan, jp });
        }
      }
    }
  }
  return;
}

function *main() {
  const rules   = require('./lib/rules');
  const config = nconf.get('rules');
  
  const errors = validateConfig( rules, config );
  
  if( errors.length > 0 ) throw { message : 'Configuration errors', errors };

  if( nconf.get( 'plan' ) ) {
    let plan = new Plan();
    let target = plan.parse( fs.readFileSync( nconf.get( 'plan' ), 'utf8' ) );
    yield validatePlan( rules, config, target.add );
    console.log( target );
  }

  return rules;  
}

function handleError( error ) {
  console.log( error );
  process.exit( 1 );
}

function handleSuccess( value ) {
  console.log( value );
  process.exit( 0 );
}

co( main ).catch( handleError ).then( handleSuccess );


