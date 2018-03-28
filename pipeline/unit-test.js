const cp = require('child_process');
const path = require('path');

let result = cp.execSync('npm test -- --coverage', {
    cwd: path.join(__dirname,'../src'),
}).toString();

let CodeCoverage = result.split('\n').find(x => x.includes("All files"));
let [File,Stmts,Branch,Funcs,Lines] = CodeCoverage.split('|').map( x => x.trim());
console.log(result);

let required = 90;
if(+Lines < required){
    let error = `CodeCoverage not satisfied. Current ${+Lines}%, Required: ${required}%`
    throw error;
}
