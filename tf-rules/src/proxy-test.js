'use strict';
const url = require( 'url' );
const _ = require( 'lodash' );

const HTTPS_PROXY = 'https://x32488:Cts@1313Cts@1313@webproxy.na.ko.com';

const urlObject = url.parse( HTTPS_PROXY );

urlObject.auth = _.get( urlObject, 'auth', '' ).split(':').map( part => unescape(encodeURIComponent(part)) ).join(':')

console.log( url.format( urlObject ) );
