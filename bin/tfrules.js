'use strict';
const debug     = require('debug')('tfrules');
const fs        = require('fs');
const _         = require('lodash');
const tfRules   = require('../index');
const co        = require('co');
const getStdin  = require('get-stdin');
const nconf     = require('nconf');
const Plan      = require('tf-parse').Plan;
const colors    = require('colors');

nconf.argv()
.env()
.file({
  file: '.tfrulesrc',
  format: require('nconf-yaml')
});

function *main() {
  debug( '*main' );
  let results = null;
  const rules   = require('../lib/rules');

  if( ! nconf.get( 'rules' ) ) {
    if( nconf.get( 'config' ) ) {
      nconf.file( 'rules', {
        file: nconf.get( 'config' ),
        format: require('nconf-yaml')
      });      
    }
  }
  
  if( ! nconf.get( 'rules' ) ) {
    console.log( colors.red( 'ERR!' ), ` Could not load configuration from .tfrulesrc file in the ${process.cwd()}. Specify the location of the file using --config` );
    process.exit( 1 );
  }
  
  const config = nconf.get('rules');

  debug( 'Validating config...' );
  
  const errors = tfRules.validateConfig( rules, config );
  
  if( errors.length > 0 ) throw { message : 'Configuration errors', errors };
  
  let inputPlan = '';
  let plan = new Plan();

  if( nconf.get( 'plan' ) ) {
    inputPlan = fs.readFileSync( nconf.get( 'plan' ), 'utf8' );
  } else {
    inputPlan = yield getStdin();
  }
  
  debug( inputPlan );
  
  inputPlan = inputPlan || '';
  
  if( inputPlan.length == 0) {
    console.log( colors.red( 'ERR!' ), " terraform plan input must be specified as a file using --plan or come from stdin" );
    process.exit( 1 );
  }

  debug( 'Parsing plan' );
  let target = plan.parse( inputPlan );
  debug( 'Calling validatePlan' );
  results = yield tfRules.validatePlan( rules, config, target.add );

  return results;
}

function handleError( error ) {
  console.log( error );
  process.exit( 1 );
}

function handleSuccess( value ) {
  let results = _.filter( value, { valid : 'success' } );
  if( results.length != value.length ) {
    process.exit( 1 );
  } else {
    process.exit( 0 );
  }
}

co( main ).catch( handleError ).then( handleSuccess );

