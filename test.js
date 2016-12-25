'use strict';

const foo = {
  meta : 1,
  create(node) {
    return 'bar';
  }
};

function main() {
  foo.create();
}

main();