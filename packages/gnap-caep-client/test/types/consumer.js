// @ts-check
// A JavaScript app using the library, type-checked from the package's declarations (editors do the same).
import { GNAPClient, SSFReceiver, TokenManager } from 'gnap-caep-client';

export async function app() {
  const client = await GNAPClient.discover({ grantEndpoint: 'https://as.example.com/gnap', access: ['ssf.read'] });
  const tokens = new TokenManager(client);
  const receiver = new SSFReceiver({
    transmitterIssuer: 'https://as.example.com',
    authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
  });
  receiver.onSessionRevoked((evt) => console.log(evt.name, evt.jti));
  // @ts-expect-error a handler must be a function
  receiver.onTokenClaimsChange(42);
}
