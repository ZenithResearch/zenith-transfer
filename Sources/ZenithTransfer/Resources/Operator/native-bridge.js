/* Trusted bundled UI only. No remote scripts or direct web networking. */
(() => {
  const config = globalThis.ZenithOperatorConfiguration;
  const call = (method, args = {}) => webkit.messageHandlers.operator.postMessage({method, ...args});
  let saved = config.pending, writes = Promise.resolve();
  const key = 'devgraph.operator-pending.v1:' + config.origin;
  const storage = {
    getItem(k) { if(k !== key) throw Error('invalid_recovery_record'); return saved; },
    setItem(k, value) {
      if(k !== key) throw Error('invalid_recovery_record'); saved = value;
      writes = writes.then(() => call('save', {record:value}));
      // Surface persistence errors through the next consent/HTTP step; never
      // dispatch until the durable record write has succeeded.
      writes.catch(() => {});
    },
    removeItem(k) {
      if(k !== key) throw Error('invalid_recovery_record'); saved = null;
      writes = writes.then(() => call('clear')); writes.catch(() => {});
    }
  };
  const wallet = {requestIdentity:null, async approveAccess(challenge) {
    await writes;
    return JSON.parse(await call('approve', {challenge:JSON.stringify(challenge)}));
  }};
  const mounts = new Set();
  let identityGeneration = 0;
  const changed = message => {
    for (const {element, onChange} of mounts) {
      element.textContent = message;
      onChange();
    }
  };
  const refreshIdentity = async () => {
    const generation = ++identityGeneration;
    try {
      const identity = JSON.parse(await call('identity'));
      if (generation !== identityGeneration) return;
      wallet.requestIdentity = identity;
      changed('');
    } catch {
      if (generation !== identityGeneration) return;
      wallet.requestIdentity = null;
      changed('Use Wallet above to unlock or check your operator Wallet.');
    }
  };
  globalThis.addEventListener('zenith-operator-wallet-state', event => {
    if (event.detail?.unlocked === true) void refreshIdentity();
    else {
      ++identityGeneration;
      wallet.requestIdentity = null;
      changed('Use Unlock Wallet above to continue.');
    }
  });
  globalThis.ZenithOperator = {origin:config.origin, storage, call,
    async fetch(path, options) {
      await writes;
      const response = await call('post', {path, body:options.body});
      return {ok:response.status>=200&&response.status<300,status:response.status,
        json:async()=>JSON.parse(response.body)};
    }
  };
  globalThis.DevgraphWalletAccess = {mount(element, {onChange}) {
    mounts.add({element, onChange});
    void refreshIdentity();
    return wallet;
  }};
})();
