import { WebAuth } from 'auth0-js';

export const makeClient = () => {
  const domain = process.env.DOMAIN as string;
  const clientID = process.env.CLIENT_ID as string;
  const audience = process.env.AUDIENCE as string;

  return new WebAuth({ domain, clientID, audience })
};
