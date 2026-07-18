import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createCredentialSource, type ModelRegistryLike } from "../src/auth.js";

function fakeRegistry(overrides: Partial<ModelRegistryLike> = {}): ModelRegistryLike {
  return {
    getApiKeyForProvider: async () => "registry-token",
    getRegisteredProviderConfig: () => undefined,
    ...overrides,
  };
}

describe("createCredentialSource", () => {
  it("resolves normal API keys through the model registry", async () => {
    const source = createCredentialSource(
      fakeRegistry({ getApiKeyForProvider: async (providerId) => `${providerId}-token` }),
      () => ({ type: "oauth", access: "raw-stored-token", refresh: "refresh", expires: Date.now() + 60_000 }),
    );

    assert.equal(await source.getApiKey("kimi-coding"), "kimi-coding-token");
  });

  it("reads stored metadata without changing the credential", () => {
    const credential = {
      type: "oauth",
      access: "access-token",
      refresh: "refresh-token",
      expires: Date.now() + 60_000,
      accountId: "account-1",
    };
    const before = structuredClone(credential);
    const source = createCredentialSource(fakeRegistry(), () => credential);

    assert.deepEqual(source.readCredential("openai-codex"), before);
    assert.deepEqual(credential, before);
  });

  it("caches forced OAuth refreshes only in process", async () => {
    const stored = {
      type: "oauth",
      access: "old-access",
      refresh: "old-refresh",
      expires: Date.now() + 60_000,
    };
    let refreshes = 0;
    const source = createCredentialSource(
      fakeRegistry({
        getApiKeyForProvider: async () => "old-access",
        getRegisteredProviderConfig: () => ({
          oauth: {
            name: "Kimi",
            login: async () => stored,
            refreshToken: async (credential) => {
              refreshes++;
              assert.equal(credential.refresh, "old-refresh");
              return {
                ...credential,
                access: "new-access",
                refresh: "new-refresh",
                expires: Date.now() + 120_000,
              };
            },
            getApiKey: (credential) => credential.access,
          },
        }),
      }),
      () => stored,
    );

    assert.equal(await source.refreshOAuthToken("kimi-coding", "old-access"), "new-access");
    assert.equal(await source.getApiKey("kimi-coding"), "new-access");
    assert.equal(refreshes, 1);
    assert.equal(stored.access, "old-access");
    assert.equal(stored.refresh, "old-refresh");
  });

  it("never refreshes API-key credentials and swallows OAuth refresh errors", async () => {
    let refreshes = 0;
    const registry = fakeRegistry({
      getRegisteredProviderConfig: () => ({
        oauth: {
          name: "Kimi",
          login: async () => ({ access: "", refresh: "", expires: 0 }),
          refreshToken: async () => {
            refreshes++;
            throw new Error("refresh-token secret");
          },
          getApiKey: (credential) => credential.access,
        },
      }),
    });

    const apiKey = createCredentialSource(registry, () => ({ type: "api_key", key: "secret" }));
    assert.equal(await apiKey.refreshOAuthToken("kimi-coding", "secret"), null);

    const oauth = createCredentialSource(registry, () => ({
      type: "oauth",
      access: "old-access",
      refresh: "refresh-token",
      expires: Date.now() + 60_000,
    }));
    assert.equal(await oauth.refreshOAuthToken("kimi-coding", "old-access"), null);
    assert.equal(refreshes, 1);
  });
});
