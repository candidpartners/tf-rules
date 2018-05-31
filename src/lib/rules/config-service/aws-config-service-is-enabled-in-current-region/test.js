const AWS = require('aws-sdk');
let rule = require('./aws-config-service-is-enabled-in-current-region');
let provider=AWS;

provider.config = {region: 'us-east-1'};

const result=rule.livecheck({config:true,provider:provider}).then((r)=>{
    console.log(JSON.stringify(r));
});

