<script lang="ts">
  import { buttonVariants } from '$lib/ui';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();

  const unverified = $derived(data.error === 'email_unverified' || !data.emailVerified);
</script>

<svelte:head><title>Connect {data.clientName} · freehire</title></svelte:head>

<div class="mx-auto flex max-w-md flex-col gap-6 py-16">
  <div class="flex flex-col gap-2">
    <h1 class="text-2xl font-semibold tracking-tight">Connect {data.clientName}</h1>
    <p class="text-sm leading-relaxed text-muted-foreground">
      This host will search jobs and manage your saved applications as you. Access lasts 30 days.
      You can disconnect it from API keys at any time.
    </p>
  </div>

  {#if unverified}
    <p class="text-sm text-destructive">Verify your email before connecting a host.</p>
  {/if}

  <form method="POST" action="/api/v1/oauth/authorize" class="flex flex-wrap gap-3">
    {#each Object.entries(data.fields) as [name, value] (name)}
      <input type="hidden" {name} {value} />
    {/each}
    <button type="submit" name="decision" value="allow" disabled={unverified} class={buttonVariants({ variant: 'primary' })}>
      Allow
    </button>
    <button type="submit" name="decision" value="deny" class={buttonVariants({ variant: 'outline' })}>
      Deny
    </button>
  </form>
</div>
