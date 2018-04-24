const AWS = require("aws-sdk")
const rule = require("./aws-s3-ensure-versioning");

jest.setTimeout(10000);
describe("aws-s3-ensure-versioning",() => {
    test("Can run", async () => {
        let result = await rule.livecheck({
            config: {},
            provider: AWS
        })
        expect(result.valid).toBe("fail")
    })
})