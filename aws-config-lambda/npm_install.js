const cp = require('child_process');

cp.execSync('npm i', {cwd: __dirname + "/src"});

console.log({});