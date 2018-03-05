let rules = require('../lib/rules/index.js');
let fs = require('fs');
let _ = require('lodash');

let sanitizedRules = _.map(rules, (value,key) => {
    return {
        name: key,
        ...value
    }
});
let json = JSON.stringify(sanitizedRules,null,2);

fs.writeFileSync('src/lib/rules.json', json, 'utf8');
