const cp = require('child_process');

jest.setTimeout(20000);
describe("Snitch e2e", () => {
    it("Can run a livecheck from the command line", async () => {
        cp.execSync("node bin/snitch.js --livecheck");
    });

    it("Can run a terraform check from the command line", async () => {
        try{
            let result = cp.execSync("node bin/snitch.js");
        } catch(error){
            expect(error.status).toBe(1);
            let errorMessage = error.stdout.toString();
            expect(errorMessage.trim()).toBe("ERR!  modules plan input must be specified as a file using --plan or come from stdin");
        }

        try{
            let result = cp.execSync("node bin/snitch.js --plan lib/rules/ec2/aws-ec2-instance-tag-exists/*.txt");
        } catch(error){
            expect(error.status).toBe(1);
            let errorMessage = error.stdout.toString();
            expect(errorMessage.includes("ERR")).toBeTruthy();
            expect(errorMessage.includes("aws-ec2-instance-tag-exists")).toBeTruthy();
        }
    })
});