const AWS = require('aws-sdk');
const services = require('./services');

jest.setTimeout(10000);
describe("services", () => {

    it("Will memoize a function correctly", async () => {
       await services.IAM.GetIAMPolicies({provider: AWS});

       await new Promise(async (resolve,reject) => {
           setTimeout(() => reject("Error! Your promise didn't resolve quickly!"),1000);
           for(let i = 0; i < 10; i++){
               await services.IAM.GetIAMPolicies({provider: AWS});
           }
           resolve("Function is memoized!");
       })
    })
});