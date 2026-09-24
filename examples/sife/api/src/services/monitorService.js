import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(exec);

export const ping = async (host) => {
  const command = `ping -c 1 ${host}`;
  try {
    const { stdout, stderr } = await run(command);
    return { command, reachable: true, output: stdout || stderr };
  } catch (err) {
    return { command, reachable: false, output: err.stdout || err.stderr || err.message };
  }
};

export const probe = async (url) => {
  const response = await fetch(url, { redirect: 'manual' });
  const body = await response.text();
  return {
    url,
    status: response.status,
    contentType: response.headers.get('content-type'),
    snippet: body.slice(0, 1000),
  };
};
