import { RouteDeckError } from "./model.ts";

export type PublicActionError = { message: string; redactedDetail?: string };

/** Maps finite internal codes to localized copy without exposing backend detail. */
export function toPublicActionError(error: unknown): PublicActionError {
  if (error instanceof RouteDeckError) {
    switch (error.code) {
      case "backend-unavailable":
        return { message: "Backend RouteDeck недоступен. Перезапустите приложение." };
      case "backend-response-invalid":
        return { message: "Не удалось прочитать состояние подключения. Перезапустите RouteDeck." };
      case "capability-unavailable":
        return { message: "Эта возможность ещё не подключена к проверенному Windows-backend." };
      case "runtime-failure":
        return { message: "Локальный backend не завершил действие. Откройте безопасную диагностику и повторите попытку." };
      case "node-not-selected":
        return { message: "Сначала импортируйте и выберите сервер." };
      case "subscription-import-rejected":
        return { message: "Полученные данные не распознаны как поддерживаемая подписка. Проверьте формат источника и повторите импорт." };
      case "invalid-subscription-url":
        return { message: "Проверьте формат HTTPS URL подписки." };
      case "insecure-subscription-url":
        return { message: "Поддерживаются ссылки на подписку по HTTPS." };
      case "subscription-policy-blocked":
        return { message: "Ссылка подписки или её перенаправление не поддерживается. Используйте обычный публичный HTTPS URL." };
      case "subscription-fetch-failed":
        return { message: "Не удалось загрузить подписку через текущий сетевой путь Windows. Проверьте ссылку и повторите попытку." };
      case "subscription-response-too-large":
        return { message: "Ответ подписки превышает допустимый размер. Используйте более компактную подписку." };
      case "subscription-fetch-timeout":
        return { message: "Сервер подписки не ответил за отведённое время через текущий сетевой путь Windows. Повторите попытку позже." };
      case "subscription-invalid-encoding":
        return { message: "Сервер вернул подписку в неподдерживаемой кодировке. Нужен корректный текст UTF-8." };
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
    message: "Действие не выполнено. Технические сведения скрыты, чтобы не показать секреты.",
    redactedDetail: "Откройте безопасный диагностический отчёт или повторите действие.",
  };
}
