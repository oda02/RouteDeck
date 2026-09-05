import { RouteDeckError } from "./model.ts";

export type PublicActionError = { message: string; redactedDetail?: string };

/** Maps finite internal codes to localized copy without exposing backend detail. */
export function toPublicActionError(error: unknown): PublicActionError {
  if (error instanceof RouteDeckError) {
    switch (error.code) {
      case "preferences-save-failed":
        return { message: "Не удалось сохранить изменения. Проверьте доступ к данным приложения и повторите попытку." };
      case "invalid-routing":
          return { message: "Проверьте правила: пути приложений не должны повторяться, а порты должны быть от 1 до 65535, кроме 53 (DNS)." };
      case "backend-unavailable":
        return { message: "Не удалось связаться с RouteDeck. Перезапустите приложение." };
      case "backend-response-invalid":
        return { message: "Не удалось прочитать состояние подключения. Перезапустите RouteDeck." };
      case "capability-unavailable":
        return { message: "Эта функция пока недоступна." };
      case "tun-admin-required":
        return { message: "Не удалось запросить права Windows для TUN. Перезапустите RouteDeck и попробуйте снова." };
      case "tun-uac-cancelled":
        return { message: "Запрос прав Windows отменён. Нажмите «Подключить» ещё раз и подтвердите стандартное окно Windows." };
      case "runtime-failure":
        return {
          message: "Не удалось выполнить действие. Повторите попытку или откройте диагностику.",
          redactedDetail: error.redactedDetail,
        };
      case "node-not-selected":
        return { message: "Сначала импортируйте и выберите сервер." };
      case "subscription-import-rejected":
        return { message: "Не удалось добавить источник. Проверьте формат ссылки или конфигурации и название группы." };
      case "invalid-source-name":
        return { message: "Введите короткое название группы без ссылок и данных доступа (до 80 символов)." };
      case "server-library-full":
        return { message: "Библиотека достигла ограничения: 64 группы, 2000 серверов или 10 МБ исходных данных." };
      case "import-requires-disconnect":
        return { message: "Не удалось завершить активное соединение. Отключите RouteDeck и повторите изменение источника." };
      case "library-reload-failed":
        return { message: "Изменение сохранено, но список не обновился. Перезапустите RouteDeck перед следующей операцией с источниками." };
      case "subscription-refresh-incomplete":
        return { message: "Подписка вернула пустой или неполный список. Прежние серверы сохранены; попробуйте обновить позже." };
      case "source-changed":
        return { message: "Источник уже изменён или удалён. Перезапустите RouteDeck, чтобы обновить список." };
      case "invalid-subscription-url":
        return { message: "Проверьте ссылку на подписку." };
      case "insecure-subscription-url":
        return { message: "Ссылка на подписку должна начинаться с https://." };
      case "subscription-policy-blocked":
        return { message: "Не удалось открыть эту ссылку. Проверьте её и попробуйте снова." };
      case "subscription-fetch-failed":
        return { message: "Не удалось загрузить подписку. Проверьте ссылку и подключение к интернету." };
      case "subscription-response-too-large":
        return { message: "Ответ подписки превышает допустимый размер. Используйте более компактную подписку." };
      case "subscription-fetch-timeout":
        return { message: "Сервер подписки не ответил вовремя. Повторите попытку позже." };
      case "subscription-invalid-encoding":
        return { message: "Сервер вернул данные в неподдерживаемом формате." };
      case "empty-subscription-source":
        return { message: "Вставьте ссылку или конфигурацию сервера." };
      case "stale-subscription-preview":
        return { message: "Импорт был отменён или уже завершён. Повторите попытку." };
    }
  }
  if (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "NotAllowedError") {
    return { message: "Windows не разрешила доступ к буферу обмена. Проверьте разрешение и повторите действие." };
  }
  return {
    message: "Не удалось выполнить действие. Повторите попытку.",
    redactedDetail: "Подробности доступны в диагностике.",
  };
}
