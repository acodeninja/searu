import { exec, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import http from 'node:http';
import https from 'node:https';

const run = promisify(exec);
const runFile = promisify(execFile);

const insecureAgent = new https.Agent({ rejectUnauthorized: false });

export const ping = async (host) => {
  const command = `ping -c 1 ${host}`;
  try {
    const { stdout, stderr } = await run(command);
    return { command, reachable: true, output: stdout || stderr };
  } catch (err) {
    return { command, reachable: false, output: err.stdout || err.stderr || err.message };
  }
};

export const connectivityCheck = async (target) => {
  const args = ['-sS', '--max-time', '5', ...target.split(' ').filter(Boolean)];
  try {
    const { stdout, stderr } = await runFile('curl', args);
    return { command: `curl ${args.join(' ')}`, output: (stdout || stderr).slice(0, 1000) };
  } catch (err) {
    return {
      command: `curl ${args.join(' ')}`,
      output: (err.stdout || err.stderr || err.message).slice(0, 1000),
    };
  }
};

export const probe = (url) =>
  new Promise((resolve, reject) => {
    const target = new URL(url);
    const lib = target.protocol === 'https:' ? https : http;
    const options = target.protocol === 'https:' ? { agent: insecureAgent } : {};
    const request = lib.get(url, options, (response) => {
      let body = '';
      response.on('data', (chunk) => {
        if (body.length < 1000) {
          body += chunk;
        }
      });
      response.on('end', () =>
        resolve({
          url,
          status: response.statusCode,
          contentType: response.headers['content-type'],
          snippet: body.slice(0, 1000),
        }),
      );
    });
    request.setTimeout(8000, () => request.destroy(new Error('probe timed out')));
    request.on('error', reject);
  });
