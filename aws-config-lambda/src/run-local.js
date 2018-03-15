const sampleEvent = require('./sample-config-event.json');
const lambda = require('./index');

lambda.handler(sampleEvent, null, (error, result) => {
    if (error)
        console.error(error);
    if (result) {
        console.log(result);
    }
});