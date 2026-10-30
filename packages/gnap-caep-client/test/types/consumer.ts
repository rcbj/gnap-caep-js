// A TypeScript app using the library: this must compile, and each @ts-expect-error line must still fail.
import {
  AccountManager, CAEP, GNAPClient, GNAPError, IndexedDBKeyStore, logEventReceived, SSFReceiver, Subject, subjectMatches,
  TokenManager, type GrantSet, type SecurityEvent,
} from 'gnap-caep-client';

export async function app(): Promise<void> {
  const client: GNAPClient = await GNAPClient.discover({
    grantEndpoint: 'https://as.example.com/gnap',
    finishUri: 'https://app.example.com/callback',
    access: ['ssf.read', { type: 'photo-api', actions: ['read'] }],
    subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] },
    keyStore: new IndexedDBKeyStore(),
  });
  const { url } = await client.createGrantRequest({ context: { from: '/' } });
  void url;

  const tokens = new TokenManager(client);
  const grant: GrantSet = await client.callback('https://app.example.com/callback?hash=x&interact_ref=y');
  await tokens.set('user', grant);
  const value: string = grant.access_token;
  const sub: unknown = grant.claims?.sub;
  const sessions: string[] = grant.sessionIds();
  void value; void sub; void sessions;
  await client.fetchResource(await tokens.getTokenSet('user'), 'https://api.example.com/me');

  const receiver = new SSFReceiver({
    transmitterIssuer: 'https://as.example.com',
    authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
    onEventReceived: async (evt: SecurityEvent) => { logEventReceived(evt); },
  });
  receiver
    .onSessionRevoked((evt) => { const reason: string | undefined = evt.reasonUser?.en; void reason; })
    .onError((err, ctx) => { const phase: string = ctx.phase; void err.code; void phase; });
  receiver.onEvent(CAEP.RISK_LEVEL_CHANGE, (evt) => {
    if (subjectMatches(evt.subject ?? {}, { iss: 'https://as.example.com', sub: 'u1', sid: grant.sessionIds() })) void evt.jti;
  });
  await receiver.start({ catchUp: true });
  await receiver.addSubject(Subject.issSub('https://as.example.com', 'u1'));

  const accounts = await new AccountManager(client, {
    onActivate: async (_account, { getTokenSet }) => { await getTokenSet(); },
  }).init();
  const active: GrantSet = await accounts.getTokenSet();
  void active;
  try {
    await client.rotate(active);
  } catch (err) {
    if (err instanceof GNAPError) { const code: string = err.error; void code; }
  }

  // @ts-expect-error a handler must be a function
  receiver.onSessionRevoked('not a function');
  // @ts-expect-error an access token is a string, not a number
  const wrong: number = grant.access_token;
  void wrong;
  // @ts-expect-error access is an array of rights
  await GNAPClient.discover({ grantEndpoint: 'https://as.example.com/gnap', access: 'ssf.read' });
}
