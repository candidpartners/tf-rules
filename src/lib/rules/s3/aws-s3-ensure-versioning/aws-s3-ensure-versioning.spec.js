const AWS = require("aws-sdk");
const AWSPromiseMock = require("../../../../aws-promise-mock");
const rule = require("./aws-s3-ensure-versioning");

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("S3", "listBuckets", {
    "Buckets": [
        {
            "Name": "amzn-edi",
            "CreationDate": "2017-07-04T02:02:34.000Z"
        }
    ]
});
GoodAWS.Service("S3", "getBucketVersioning", {"Status": "Enabled"});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("S3", "listBuckets", {
    "Buckets": [
        {
            "Name": "amzn-edi",
            "CreationDate": "2017-07-04T02:02:34.000Z"
        }
    ]
});
BadAWS.Service("S3", "getBucketVersioning", {});

jest.setTimeout(10000);
describe("Can pass a livecheck", () => {
    test("Fails", async () => {
        let result = await rule.livecheck({config: {}, provider: BadAWS});
        expect(result.valid).toBe("fail")
    });

    test("Passes", async () => {
        let result = await rule.livecheck({config: {}, provider: GoodAWS});
        expect(result.valid).toBe("success")
    });
});