<script lang="ts">
  import { resolve } from '$app/paths';
  import { api } from '$lib/api';
  import { AsyncData } from '$lib/asyncData.svelte';
  import { isAuthenticated } from '$lib/auth.svelte';
  import { consumeReauthDraft } from '$lib/recentAuth';
  import { locale } from '$lib/i18n/currentLocale.svelte';
  import { t } from '$lib/i18n/t';
  import type { ApiKey, CreatedApiKey, OAuthGrant } from '$lib/types';
  import { Button, ConfirmDialog } from '$lib/ui';
  import { timeAgo } from '$lib/utils';
  import { messages } from './ApiKeysView.messages';
  import ConfirmIdentity from './ConfirmIdentity.svelte';
  import CreateApiKeyDialog from './CreateApiKeyDialog.svelte';
  import States from './States.svelte';

  // The page is a list and two dialogs. It used to be a list and a permanently open create
  // form, and the identity check was spread across both: the password input lived in that
  // form while the revoke dialog demanded a password — from behind a modal backdrop, where
  // no input is reachable. Each dialog now carries its own confirmation.
  const s = $derived(t(messages, locale()));

  let createOpen = $state(false);

  // The plaintext token of the just-created key — shown here exactly once, then
  // dismissed. It is never persisted client-side and never fetched again.
  let revealed = $state.raw<CreatedApiKey | null>(null);
  let copied = $state(false);

  // Show the fastest path to actually using the key: hand it to the CLI and
  // search. The raw Bearer-header call still works (noted in the page intro),
  // but the CLI is the intended client — see /cli.
  const cliExample = $derived(
    revealed
      ? `freehire auth login --token ${revealed.token}\nfreehire search "golang" --remote`
      : '',
  );

  // Load once the session is confirmed (the boot-time /me resolution may still be
  // in flight when the page is opened directly), mirroring MyJobsView.
  const keysData = new AsyncData<ApiKey[]>([]);
  const devicesData = new AsyncData<OAuthGrant[]>([]);
  $effect(() => {
    if (isAuthenticated()) {
      void keysData.run(() => api.listApiKeys());
      void devicesData.run(() => api.listOAuthGrants());
    }
  });
  const status = $derived(keysData.status);
  const keys = $derived(keysData.value);
  const deviceStatus = $derived(devicesData.status);
  const devices = $derived(devicesData.value);

  function onCreated(key: CreatedApiKey): void {
    revealed = key;
    copied = false;
    keysData.value = [key, ...keysData.value];
  }

  async function copyToken(): Promise<void> {
    if (!revealed) return;
    try {
      await navigator.clipboard.writeText(revealed.token);
      copied = true;
    } catch {
      copied = false;
    }
  }

  let revokeTarget = $state<ApiKey | null>(null);
  let confirmRevokeOpen = $state(false);
  let revokePassword = $state('');
  let revokeIdentity = $state<ConfirmIdentity | null>(null);

  // Reopen the revocation the member left to confirm. The key ID travels rather than the
  // key itself: the list is re-fetched on mount, so the row is looked up fresh — a stored
  // copy could be of a key that has since been revoked from another tab.
  $effect(() => {
    const pending = consumeReauthDraft('revoke-api-key');
    if (!pending) return;
    pendingRevokeId = pending.keyId;
  });
  // Held until the list arrives, since the dialog names the key and the fetch may still be
  // in flight when the draft is read.
  let pendingRevokeId = $state<number | null>(null);
  $effect(() => {
    if (pendingRevokeId === null) return;
    const key = keysData.value.find((k) => k.id === pendingRevokeId);
    if (!key) return;
    pendingRevokeId = null;
    requestRevoke(key);
  });

  function requestRevoke(key: ApiKey): void {
    revokeTarget = key;
    revokePassword = '';
    confirmRevokeOpen = true;
  }

  let deviceTarget = $state<OAuthGrant | null>(null);
  let confirmDeviceOpen = $state(false);
  let devicePassword = $state('');
  let deviceIdentity = $state<ConfirmIdentity | null>(null);
  let pendingGrantId = $state<number | null>(null);

  $effect(() => {
    const pending = consumeReauthDraft('revoke-oauth-grant');
    if (!pending) return;
    pendingGrantId = pending.grantId;
  });
  $effect(() => {
    if (pendingGrantId === null) return;
    const grant = devicesData.value.find((g) => g.id === pendingGrantId);
    if (!grant) return;
    pendingGrantId = null;
    requestDeviceRevoke(grant);
  });

  function requestDeviceRevoke(grant: OAuthGrant): void {
    deviceTarget = grant;
    devicePassword = '';
    confirmDeviceOpen = true;
  }

  async function revokeDevice(): Promise<void> {
    const grant = deviceTarget;
    if (!grant) return;
    try {
      if (!(await deviceIdentity?.prove())) throw new Error(s.deviceErrors.confirmFirst);
      await api.revokeOAuthGrant(grant.id);
      devicesData.value = devicesData.value.filter((g) => g.id !== grant.id);
      devicePassword = '';
    } catch (error) {
      throw new Error(deviceIdentity?.handleRefusal(error) ?? s.deviceErrors.revokeFailed, {
        cause: error,
      });
    }
  }

  async function revoke(): Promise<void> {
    const key = revokeTarget;
    if (!key) return;
    try {
      if (!(await revokeIdentity?.prove())) throw new Error(s.errors.confirmFirst);
      await api.revokeApiKey(key.id);
      keysData.value = keysData.value.filter((k) => k.id !== key.id);
      if (revealed?.id === key.id) revealed = null;
      revokePassword = '';
    } catch (error) {
      // ConfirmDialog shows a thrown message in place and holds itself open, which is what
      // keeps the confirmation the member needs on screen beside the failure that asked
      // for it. Identity refusals are worded by the component that asked for the proof.
      throw new Error(revokeIdentity?.handleRefusal(error) ?? s.errors.revokeFailed, {
        cause: error,
      });
    }
  }
</script>

{#if !isAuthenticated()}
  <p class="py-12 text-center text-sm text-muted-foreground">
    {s.signedOut}
  </p>
{:else}
  <div class="flex flex-col gap-6">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="flex flex-col gap-1">
        <h1 class="text-2xl font-semibold tracking-tight">{s.title}</h1>
        <p class="text-sm text-muted-foreground">
          {s.intro.lead}
          <a href={resolve('/cli')} class="font-medium text-foreground underline-offset-4 hover:underline">{s.intro.cliLink}</a>{s.intro.orSendDirectly}
          <code class="rounded bg-muted px-1 py-0.5 font-mono text-xs">Authorization: Bearer &lt;key&gt;</code>{s.intro.seeThe}
          <a href={resolve('/docs/api')} class="font-medium text-foreground underline-offset-4 hover:underline">{s.intro.apiReferenceLink}</a>
          {s.intro.apiReferenceTail}
        </p>
      </div>
      <Button variant="primary" onclick={() => (createOpen = true)}>{s.form.create}</Button>
    </div>

    {#if revealed}
      <div class="flex flex-col gap-3 rounded-lg border border-border bg-secondary/40 p-4">
        <div class="flex items-start justify-between gap-3">
          <div class="flex flex-col gap-0.5">
            <p class="text-sm font-medium">{s.reveal.newKeyPrefix} “{revealed.name}”</p>
            <p class="text-xs text-muted-foreground">{s.reveal.copyNow}</p>
          </div>
          <button
            type="button"
            onclick={() => (revealed = null)}
            aria-label={s.reveal.dismiss}
            class="text-muted-foreground transition-colors hover:text-foreground"
          >
            ✕
          </button>
        </div>
        <div class="flex items-center gap-2">
          <code class="flex-1 overflow-x-auto rounded bg-background px-3 py-2 font-mono text-sm"
            >{revealed.token}</code
          >
          <Button variant="secondary" size="sm" onclick={copyToken}>
            {copied ? s.reveal.copied : s.reveal.copy}
          </Button>
        </div>
        <pre
          class="overflow-x-auto rounded bg-background px-3 py-2 font-mono text-xs text-muted-foreground">{cliExample}</pre>
        <p class="text-xs text-muted-foreground">
          {s.reveal.newToCli}
          <a href={resolve('/cli')} class="font-medium text-foreground underline-offset-4 hover:underline">{s.reveal.commandReferenceLink}</a>.
        </p>
      </div>
    {/if}

    {#if status === 'loading'}
      <States state="loading" />
    {:else if status === 'error'}
      <States state="error" message={s.list.loadError} />
    {:else if keys.length === 0}
      <States state="empty" message={s.list.empty} />
    {:else}
      <ul aria-label={s.title} class="flex flex-col divide-y divide-border rounded-lg border border-border">
        {#each keys as key (key.id)}
          <li class="flex items-center justify-between gap-3 px-4 py-3">
            <div class="flex min-w-0 flex-col gap-0.5">
              <span class="truncate text-sm font-medium">{key.name}</span>
              <span class="font-mono text-xs text-muted-foreground">{key.token_prefix}…</span>
              <span class="text-xs text-muted-foreground">
                {s.list.createdPrefix}
                {timeAgo(key.created_at, locale())} ·
                {key.last_used_at
                  ? `${s.list.lastUsedPrefix} ${timeAgo(key.last_used_at, locale())}`
                  : s.list.neverUsed}
                {#if key.expires_at}· {s.list.expiresPrefix} {timeAgo(key.expires_at, locale())}{/if}
              </span>
            </div>
            <Button variant="ghost" size="sm" onclick={() => requestRevoke(key)}>
              {s.list.revoke}
            </Button>
          </li>
        {/each}
      </ul>
    {/if}

    <section class="flex flex-col gap-3 border-t border-border pt-6">
      <div class="flex flex-col gap-1">
        <h2 class="text-lg font-semibold tracking-tight">{s.devices.title}</h2>
        <p class="text-sm text-muted-foreground">{s.devices.intro}</p>
      </div>
      {#if deviceStatus === 'loading'}
        <States state="loading" />
      {:else if deviceStatus === 'error'}
        <States state="error" message={s.devices.loadError} />
      {:else if devices.length === 0}
        <States state="empty" message={s.devices.empty} />
      {:else}
        <ul aria-label={s.devices.title} class="flex flex-col divide-y divide-border rounded-lg border border-border">
          {#each devices as device (device.id)}
            <li class="flex items-center justify-between gap-3 px-4 py-3">
              <div class="flex min-w-0 flex-col gap-0.5">
                <span class="truncate text-sm font-medium">{device.client_name}</span>
                <span class="text-xs text-muted-foreground">
                  {s.devices.connectedPrefix}
                  {timeAgo(device.created_at, locale())} ·
                  {device.last_used_at
                    ? `${s.devices.lastUsedPrefix} ${timeAgo(device.last_used_at, locale())}`
                    : s.devices.neverUsed}
                  · {s.devices.expiresPrefix} {timeAgo(device.expires_at, locale())}
                </span>
              </div>
              <Button variant="ghost" size="sm" onclick={() => requestDeviceRevoke(device)}>
                {s.devices.revoke}
              </Button>
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  </div>

  <CreateApiKeyDialog bind:open={createOpen} {onCreated} />

  <ConfirmDialog
    bind:open={confirmRevokeOpen}
    title={`${s.revokeDialog.titlePrefix} "${revokeTarget?.name ?? ''}"${s.revokeDialog.titleSuffix}`}
    description={s.revokeDialog.description}
    confirmLabel={s.revokeDialog.confirmLabel}
    variant="destructive"
    onConfirm={revoke}
  >
    <!-- The fix for the original report. ConfirmDialog has always accepted `children`;
         this page simply never passed any, so the dialog asked for a password that only
         existed on the page behind its own backdrop. -->
    <ConfirmIdentity
      bind:this={revokeIdentity}
      bind:password={revokePassword}
      returnTo="/my/api-keys"
      prompt={s.revokeDialog.confirmPrompt}
      draft={() => ({ surface: 'revoke-api-key', keyId: revokeTarget?.id ?? 0 })}
      active={confirmRevokeOpen}
    />
  </ConfirmDialog>

  <ConfirmDialog
    bind:open={confirmDeviceOpen}
    title={`${s.deviceRevoke.titlePrefix} "${deviceTarget?.client_name ?? ''}"${s.deviceRevoke.titleSuffix}`}
    description={s.deviceRevoke.description}
    confirmLabel={s.deviceRevoke.confirmLabel}
    variant="destructive"
    onConfirm={revokeDevice}
  >
    <ConfirmIdentity
      bind:this={deviceIdentity}
      bind:password={devicePassword}
      returnTo="/my/api-keys"
      prompt={s.deviceRevoke.confirmPrompt}
      draft={() => ({ surface: 'revoke-oauth-grant', grantId: deviceTarget?.id ?? 0 })}
      active={confirmDeviceOpen}
    />
  </ConfirmDialog>
{/if}
