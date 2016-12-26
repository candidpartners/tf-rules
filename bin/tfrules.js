'use strict';

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
  let results = null;
  const rules   = require('../lib/rules');
  const config = nconf.get('rules');
  
  const errors = tfRules.validateConfig( rules, config );
  
  if( errors.length > 0 ) throw { message : 'Configuration errors', errors };
  
  let inputPlan = '';
  let plan = new Plan();

  if( nconf.get( 'plan' ) ) {
    inputPlan = fs.readFileSync( nconf.get( 'plan' ), 'utf8' );
  } else {
    inputPlan = yield getStdin();
  }
  
  inputPlan = inputPlan || '';
  
  if( inputPlan.length == 0) {
    console.log( colors.red( 'ERR!' ), " terraform plan input must be specified as a file using --plan or come from stdin" );
    process.exit( 1 );
  }
  
  let target = plan.parse( inputPlan );
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

