#!/usr/bin/env node
const program = require('commander');
const { exec } = require('child_process');

const AUDIT_BASE_COMMAND = 'npm audit';
const SEPARATOR = ',';
const SPLIT_REGEX = /(https:\/\/(nodesecurity.io|npmjs.com)\/advisories\/)/;
const DIGIT_REGEX = /^\d+$/;

function isNumber(string) {
  return DIGIT_REGEX.test(string);
}

function unique(value, index, self) {
  return self.indexOf(value) === index;
}

let userExceptionIds = [];

program
  .version('0.1.1');

program
  .command('audit')
  .description('execute npm audit')
  .option("-i, --ignore <ids>", "Vulnerability IDs to ignore.")
  .option("-r, --registry <npm registry url>", "The registry to be used for the audit.")
  .action(function(options) {
    let audit_command = AUDIT_BASE_COMMAND;

    if (options && options.ignore) {
      userExceptionIds = options.ignore.split(SEPARATOR);
      console.info('Exception vulnerabilities ID(s): ', userExceptionIds);
    }

    if (options && options.registry) {
      audit_command = AUDIT_BASE_COMMAND + ' --registry ' + options.registry;
    }

    // Execute `npm audit` command to get the security report
    const audit = exec(audit_command);

    // stdout
    audit.stdout.on('data', data => {
      // Split the security report string by the URL at the end, and get the first 4 characters;
      // This might contains of other words than the IDs,
      // eg: ['===', 'http', 'node', '534', 'http', 'node', '118', 'http', 'node', '146', 'http', 'node', '975', 'http', 'node', '976']
      const rawIds = data.split(SPLIT_REGEX).map(str => str.substring(0, 4).trim());
      // Remove everything except for numbers from the array
      const numberIds = rawIds.filter(str => isNumber(str));
      // Remove duplicates
      const uniqueIds = numberIds.filter(unique);
      // Check if there is any more exceptions other than the user selected to ignore
      const vulnerabilities = uniqueIds.filter(id => (userExceptionIds.indexOf(id) === -1));
      // Throw error if found more exceptions
      if (vulnerabilities.length > 0) {
        const message = `${vulnerabilities.length} vulnerabilities found. Node security advisories: ${vulnerabilities}`;
        throw new Error(message);
      }
      else {
        console.info(data);
        console.info('All good!');
      }
    });

    // stderr
    audit.stderr.on('data', data => {
      console.info(data);
    });
  });

program.parse(process.argv);
