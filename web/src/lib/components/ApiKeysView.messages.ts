import { defineMessages } from '$lib/i18n/t';

// The `Authorization: Bearer <key>` header and the CLI command in the reveal box
// are protocol, not prose — they stay English in every locale, and are composed in
// the component rather than living here.
export const messages = defineMessages(
  {
    headTitle: 'API keys — freehire',
    signedOut: 'Sign in to create and manage API keys.',
    title: 'API keys',
    intro: {
      // The paragraph is split around its two inline links and the header code
      // sample, in reading order. Every segment ENDS a phrase and the next one
      // opens with its own punctuation, so no segment needs a leading or
      // trailing space to read correctly — and the sentence's final period is a
      // literal in the markup, since it is the same character in every locale.
      lead: 'Reach the API without a browser — search, open jobs, and track applications from a script. Use the',
      cliLink: 'freehire CLI',
      orSendDirectly: ', or send the key directly as',
      seeThe: '. See the',
      apiReferenceLink: 'API reference',
      // The one segment that FOLLOWS a link, so it opens a phrase rather than
      // ending one and takes its leading space from the markup. It exists so the
      // English sentence keeps its original order — inverting the clause to avoid
      // a fourth key would have been a copy change smuggled in as a refactor.
      apiReferenceTail: 'for every endpoint and filter.',
    },
    reveal: {
      // "New key “<name>”" — the component supplies the quoted name.
      newKeyPrefix: 'New key',
      copyNow: 'Copy it now — it won’t be shown again.',
      dismiss: 'Dismiss',
      copy: 'Copy',
      copied: 'Copied',
      newToCli: 'New to the CLI? See the',
      commandReferenceLink: 'command reference',
    },
    // What is left of the old create form: the page now only needs the label on the button
    // that opens the dialog. The fields themselves live in CreateApiKeyDialog.messages.ts.
    form: {
      create: 'Create key',
    },
    errors: {
      confirmFirst: 'Confirm it is you before revoking a key.',
      revokeFailed: 'Could not revoke the key. Please try again.',
    },
    list: {
      loadError: "Couldn't load your API keys.",
      empty: 'No API keys yet. Create one to use the API from a script.',
      // "Created <2 days ago> · <last used 3 hours ago|never used> · expires <in a month>"
      createdPrefix: 'Created',
      lastUsedPrefix: 'last used',
      neverUsed: 'never used',
      expiresPrefix: 'expires',
      revoke: 'Revoke',
    },
    revokeDialog: {
      // "Revoke "<name>"?" — the component supplies the quoted name.
      titlePrefix: 'Revoke',
      titleSuffix: '?',
      description: 'Any script using it stops working immediately.',
      confirmPrompt: 'Revoking a credential is a security change, so we check it is you.',
      confirmLabel: 'Revoke',
    },
    devices: {
      title: 'Connected devices',
      intro: 'An AI host that signs in through the browser. Access lasts 30 days from when you allowed it.',
      loadError: "Couldn't load connected devices.",
      empty: 'No AI hosts are connected.',
      connectedPrefix: 'Connected',
      lastUsedPrefix: 'last used',
      neverUsed: 'never used',
      expiresPrefix: 'expires',
      revoke: 'Revoke',
    },
    deviceRevoke: {
      titlePrefix: 'Disconnect',
      titleSuffix: '?',
      description: 'The host loses access immediately. It can connect again only if you allow it.',
      confirmPrompt: 'Disconnecting a device is a security change, so we check it is you.',
      confirmLabel: 'Disconnect',
    },
    deviceErrors: {
      confirmFirst: 'Confirm it is you before disconnecting a device.',
      revokeFailed: 'Could not disconnect the device. Please try again.',
    },
  },
  {
    ru: {
      headTitle: 'API-ключи — freehire',
      signedOut: 'Войдите, чтобы создавать API-ключи и управлять ими.',
      title: 'API-ключи',
      intro: {
        lead: 'Обращайтесь к API без браузера — ищите вакансии, открывайте их и ведите отклики из скрипта. Используйте',
        cliLink: 'freehire CLI',
        orSendDirectly: ' или передавайте ключ напрямую как',
        seeThe: '. Смотрите',
        apiReferenceLink: 'справочник API',
        apiReferenceTail: '— там все эндпоинты и фильтры.',
      },
      reveal: {
        newKeyPrefix: 'Новый ключ',
        copyNow: 'Скопируйте сейчас — второй раз он показан не будет.',
        dismiss: 'Закрыть',
        copy: 'Скопировать',
        copied: 'Скопировано',
        newToCli: 'Впервые работаете с CLI? Откройте',
        commandReferenceLink: 'справочник команд',
      },
      form: {
        create: 'Создать ключ',
      },
      errors: {
        confirmFirst: 'Подтвердите, что это вы, прежде чем отзывать ключ.',
        revokeFailed: 'Не удалось отозвать ключ. Попробуйте ещё раз.',
      },
      list: {
        loadError: 'Не удалось загрузить ваши API-ключи.',
        empty: 'API-ключей пока нет. Создайте ключ, чтобы обращаться к API из скрипта.',
        createdPrefix: 'Создан',
        lastUsedPrefix: 'последний раз использован',
        neverUsed: 'ни разу не использован',
        expiresPrefix: 'истекает',
        revoke: 'Отозвать',
      },
      revokeDialog: {
        titlePrefix: 'Отозвать',
        titleSuffix: '?',
        description: 'Любой скрипт, который им пользуется, перестанет работать немедленно.',
        confirmPrompt: 'Отзыв ключа — изменение настроек безопасности, поэтому мы проверяем, что это вы.',
        confirmLabel: 'Отозвать',
      },
      devices: {
        title: 'Подключённые устройства',
        intro: 'ИИ-клиент, который входит через браузер. Доступ действует 30 дней с момента, когда вы его разрешили.',
        loadError: 'Не удалось загрузить подключённые устройства.',
        empty: 'Ни один ИИ-клиент не подключён.',
        connectedPrefix: 'Подключено',
        lastUsedPrefix: 'последний раз использовано',
        neverUsed: 'ни разу не использовано',
        expiresPrefix: 'истекает',
        revoke: 'Отозвать',
      },
      deviceRevoke: {
        titlePrefix: 'Отключить',
        titleSuffix: '?',
        description: 'Клиент сразу теряет доступ. Подключить его снова можно только с вашего разрешения.',
        confirmPrompt: 'Отключение устройства — изменение настроек безопасности, поэтому мы проверяем, что это вы.',
        confirmLabel: 'Отключить',
      },
      deviceErrors: {
        confirmFirst: 'Подтвердите, что это вы, прежде чем отключать устройство.',
        revokeFailed: 'Не удалось отключить устройство. Попробуйте ещё раз.',
      },
    },
  },
);
