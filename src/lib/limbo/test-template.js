const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("", "", {});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("", "", {});

describe("", () => {

    test("", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("")
    });

    test("", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);