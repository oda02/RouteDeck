import { RouteDeckError } from "./model.ts";

export type PublicActionError = { message: string; redactedDetail?: string };

/** Maps finite internal codes to localized copy without exposing backend detail. */
export function toPublicActionError(error: unknown): PublicActionError {
  if (error instanceof RouteDeckError) {
    switch (error.code) {
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
        return { message: "Полученные данные не распознаны как поддерживаемая подписка. Проверьте формат источника и повторите импорт." };
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
        return { message: "Ссылка на подписку пустая." };
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
