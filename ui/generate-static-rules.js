let rules = require('../src/lib/rules/index.js');
let fs = require('fs');
let _ = require('lodash');

let sanitizedRules = _.map(rules, (rule,key) => {
    let tags = [];

    //Make sure recommended is first
    if(rule.docs.recommended) tags.push("Recommended");
    if(_.isFunction(rule.validate)) tags.push("Terraform");
    if(_.isFunction(rule.livecheck)) tags.push("Livecheck");

    return {
        name: key,
        ...rule,
        tags: tags
    }
});

let json = JSON.stringify(sanitizedRules,null,2);

fs.writeFileSync('src/lib/rules.json', json, 'utf8');
