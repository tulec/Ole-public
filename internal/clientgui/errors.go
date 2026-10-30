//go:build windows

package clientgui

import (
	"fmt"
	"os"
	"strings"
)

type guiErrorMessage struct {
	Title   string
	Message string
}

func detectGUILocale() string {
	candidates := []string{
		strings.TrimSpace(os.Getenv("OLE_GUI_LOCALE")),
		strings.TrimSpace(os.Getenv("LC_ALL")),
		strings.TrimSpace(os.Getenv("LC_MESSAGES")),
		strings.TrimSpace(os.Getenv("LANG")),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		value := strings.ToLower(candidate)
		if strings.HasPrefix(value, "ru") {
			return "ru"
		}
		break
	}
	return "en"
}

func formatGUIError(err error) guiErrorMessage {
	return formatGUIErrorForLocale(err, detectGUILocale())
}

func formatGUIErrorForLocale(err error, locale string) guiErrorMessage {
	raw := ""
	if err != nil {
		raw = strings.TrimSpace(err.Error())
	}
	if raw == "" {
		if locale == "ru" {
			return guiErrorMessage{
				Title:   "Ошибка Ole",
				Message: "Произошла неизвестная ошибка.",
			}
		}
		return guiErrorMessage{
			Title:   "Ole Error",
			Message: "An unknown error occurred.",
		}
	}

	lower := strings.ToLower(raw)
	switch {
	case isLocalAgentUnreachable(lower):
		return unreachableAgentError(locale, raw)
	case containsAny(lower, "invalid credentials", "invalid password"):
		return invalidCredentialsError(locale, raw)
	case containsAny(lower, "minimum supported version", "older than the minimum supported version", "upgrade required"):
		return compatibilityError(locale, raw)
	case strings.Contains(lower, "update channel") && strings.Contains(lower, "is not configured"):
		return updateChannelUnavailableError(locale, raw)
	case strings.Contains(lower, "update manifest url is not configured"):
		return updateManifestMissingError(locale, raw)
	case strings.Contains(lower, "no rollback release is available"):
		return rollbackUnavailableError(locale, raw)
	case strings.Contains(lower, "update check is already running"):
		return updateBusyError(locale, raw)
	case strings.Contains(lower, "no update is currently available"):
		return noUpdateAvailableError(locale, raw)
	case strings.Contains(lower, "no downloaded update is available to install"):
		return noDownloadedUpdateError(locale, raw)
	case containsAny(lower, "minimum supported version for this update", "maximum supported version", "current server version is compatible with this update"):
		return updateCompatibilityPolicyError(locale, raw)
	case strings.Contains(lower, "checksum mismatch"):
		return updateChecksumError(locale, raw)
	case containsAny(lower, "not connected to ole service", "sign in first", "no active session"):
		return signInRequiredError(locale, raw)
	case strings.Contains(lower, "no persisted session is available to reconnect"):
		return reconnectUnavailableError(locale, raw)
	case strings.Contains(lower, "select a network first"):
		return selectionRequiredError(locale, "network", raw)
	case strings.Contains(lower, "select a session first"):
		return selectionRequiredError(locale, "session", raw)
	case strings.Contains(lower, "select a device first"):
		return selectionRequiredError(locale, "device", raw)
	case strings.Contains(lower, "select an audit preset first"):
		return selectionRequiredError(locale, "audit-preset", raw)
	case strings.Contains(lower, "device fingerprint is not available"):
		return fingerprintUnavailableError(locale, raw)
	case strings.Contains(lower, "device approval required"):
		return deviceApprovalRequiredError(locale, raw)
	case strings.Contains(lower, "unsupported name resolution mode"):
		return nameResolutionModeError(locale, raw)
	case strings.Contains(lower, "unsupported routing policy"):
		return routingPolicyError(locale, raw)
	case strings.Contains(lower, "file transfer max payload bytes must be between"):
		return fileTransferPolicyRangeError(locale, raw)
	case strings.Contains(lower, "file transfer max bytes must be a whole number"):
		return wholeNumberFieldError(locale, "File Transfer Max Bytes", raw)
	case strings.Contains(lower, "file transfers are disabled for this network"):
		return fileTransfersDisabledError(locale, raw)
	case strings.Contains(lower, "dns label"):
		return dnsLabelError(locale, raw)
	case strings.Contains(lower, "audit preset name is required"):
		return auditPresetNameRequiredError(locale, raw)
	case strings.Contains(lower, "audit from-unix must be a whole number"):
		return wholeNumberFieldError(locale, "From Unix", raw)
	case strings.Contains(lower, "audit to-unix must be a whole number"):
		return wholeNumberFieldError(locale, "To Unix", raw)
	case strings.Contains(lower, "ttl must be numeric"):
		return wholeNumberFieldError(locale, "TTL sec", raw)
	case strings.Contains(lower, "max uses must be numeric"):
		return wholeNumberFieldError(locale, "Max uses", raw)
	case strings.Contains(lower, "adapter mtu must be a whole number"):
		return wholeNumberFieldError(locale, "Adapter MTU", raw)
	case strings.Contains(lower, "adapter mtu must be between"):
		return adapterMTURangeError(locale, raw)
	case strings.Contains(lower, "endpoint is required to rejoin network"):
		return endpointRequiredError(locale, raw)
	case containsAny(lower, "invite expired", "invite exhausted"):
		return inviteError(locale, raw)
	case containsAny(lower, "user is banned", "device is not active", "device is already revoked", "unauthorized"):
		return authorizationError(locale, raw)
	case containsAny(lower, "no remote candidates available", "direct path unavailable", "no relay servers configured", "relay path unavailable", "relay failover unavailable"):
		return peerPathError(locale, raw)
	case containsAny(lower, "packet quota exceeded", "byte quota exceeded"):
		return relayQuotaError(locale, raw)
	case containsAny(lower, "entity not found", "not found"):
		return notFoundError(locale, raw)
	case strings.Contains(lower, "request failed with status"):
		return apiRequestError(locale, raw)
	default:
		return genericGUIError(locale, raw)
	}
}

func isLocalAgentUnreachable(lower string) bool {
	return containsAny(lower,
		"127.0.0.1:5858",
		"connectex",
		"connection refused",
		"actively refused",
		"no connection could be made",
		"client.timeout exceeded",
		"no such host",
	)
}

func containsAny(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func unreachableAgentError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Ole Agent недоступен",
			Message: "Локальный Ole Agent не отвечает.\n\n" +
				"Что сделать:\n" +
				"- Запустите `cmd/agent` или Windows service.\n" +
				"- Проверьте, что GUI может обратиться к `127.0.0.1:5858`.\n" +
				"- Нажмите `Refresh Agent` и повторите действие.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Ole Agent Unreachable",
		Message: "The local Ole Agent is not responding.\n\n" +
			"What to do:\n" +
			"- Start `cmd/agent` or the Windows service.\n" +
			"- Check that the GUI can reach `127.0.0.1:5858`.\n" +
			"- Press `Refresh Agent` and try again.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func invalidCredentialsError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Не удалось войти",
			Message: "Email или пароль не подошли.\n\n" +
				"Что сделать:\n" +
				"- Проверьте email и пароль.\n" +
				"- Если у agent уже есть сохранённая сессия, попробуйте `Reconnect`.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Sign-In Failed",
		Message: "The email or password did not match.\n\n" +
			"What to do:\n" +
			"- Check the email and password.\n" +
			"- If the agent already has a saved session, try `Reconnect`.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func compatibilityError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Нужна более новая версия клиента",
			Message: "Этот сервер требует более новую версию Ole Desktop.\n\n" +
				"Что сделать:\n" +
				"- Обновите клиент до минимально поддерживаемой версии.\n" +
				"- Затем нажмите `Refresh Agent` и повторите вход.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Client Upgrade Required",
		Message: "This server requires a newer Ole Desktop version.\n\n" +
			"What to do:\n" +
			"- Upgrade the client to the minimum supported version.\n" +
			"- Press `Refresh Agent` and try signing in again.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func updateManifestMissingError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Auto-update не настроен",
			Message: "Локальный Ole Agent не знает, откуда брать манифест обновлений.\n\n" +
				"Что сделать:\n" +
				"- Настройте `OLE_UPDATE_MANIFEST_URL` для Ole Agent.\n" +
				"- Затем нажмите `Check Updates` ещё раз.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Auto-Update Not Configured",
		Message: "The local Ole Agent does not have an update manifest URL yet.\n\n" +
			"What to do:\n" +
			"- Configure `OLE_UPDATE_MANIFEST_URL` for the Ole Agent.\n" +
			"- Then press `Check Updates` again.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func updateChannelUnavailableError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Канал обновлений недоступен",
			Message: "Для выбранного канала у локального Ole Agent не настроен manifest.\n\n" +
				"Что сделать:\n" +
				"- Проверьте `OLE_UPDATE_STABLE_MANIFEST_URL` и `OLE_UPDATE_BETA_MANIFEST_URL`.\n" +
				"- Выберите другой канал или настройте missing manifest URL.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Update Channel Unavailable",
		Message: "The selected update channel does not have a configured manifest URL.\n\n" +
			"What to do:\n" +
			"- Check `OLE_UPDATE_STABLE_MANIFEST_URL` and `OLE_UPDATE_BETA_MANIFEST_URL`.\n" +
			"- Pick a different channel or configure the missing manifest URL.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func updateBusyError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Проверка обновлений уже идёт",
			Message: "Ole Agent уже проверяет наличие новой версии.\n\n" +
				"Что сделать:\n" +
				"- Подождите несколько секунд.\n" +
				"- Затем обновите diagnostics или повторите действие.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Update Check Already Running",
		Message: "The Ole Agent is already checking for updates.\n\n" +
			"What to do:\n" +
			"- Wait a few seconds.\n" +
			"- Then refresh diagnostics or try again.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func noUpdateAvailableError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Обновление не найдено",
			Message: "Для этого клиента сейчас нет более новой версии.\n\n" +
				"Что сделать:\n" +
				"- Оставьте текущую версию.\n" +
				"- Позже снова нажмите `Check Updates`.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "No Update Available",
		Message: "There is no newer Ole Desktop version for this client right now.\n\n" +
			"What to do:\n" +
			"- Keep using the current build.\n" +
			"- Press `Check Updates` again later.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func noDownloadedUpdateError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Сначала скачайте обновление",
			Message: "Установщик обновления ещё не загружен локально.\n\n" +
				"Что сделать:\n" +
				"- Сначала нажмите `Download Update`.\n" +
				"- После этого используйте `Install Update`.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Download The Update First",
		Message: "The updated installer is not downloaded locally yet.\n\n" +
			"What to do:\n" +
			"- Press `Download Update` first.\n" +
			"- Then use `Install Update`.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func updateChecksumError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Проверка обновления не прошла",
			Message: "Загруженный установщик не прошёл SHA-256 проверку.\n\n" +
				"Что сделать:\n" +
				"- Повторите `Download Update`.\n" +
				"- Если ошибка повторяется, проверьте release assets и manifest.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Update Verification Failed",
		Message: "The downloaded installer did not pass SHA-256 verification.\n\n" +
			"What to do:\n" +
			"- Run `Download Update` again.\n" +
			"- If it still fails, verify the release assets and update manifest.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func rollbackUnavailableError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Откат недоступен",
			Message: "Для этого release manifest не объявляет rollback installer.\n\n" +
				"Что сделать:\n" +
				"- Оставайтесь на текущей сборке или переключитесь на другой update channel.\n" +
				"- Если rollback должен быть доступен, проверьте manifest metadata.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Rollback Unavailable",
		Message: "This release manifest does not advertise a rollback installer.\n\n" +
			"What to do:\n" +
			"- Stay on the current build or switch to another update channel.\n" +
			"- If rollback should exist, verify the manifest metadata.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func updateCompatibilityPolicyError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Обновление заблокировано policy",
			Message: "Выбранное обновление не подходит текущей версии сервера.\n\n" +
				"Что сделать:\n" +
				"- Проверьте `Service Health` и `Agent Diagnostics` для policy details.\n" +
				"- Переключитесь на другой update channel или используйте rollback build, если он доступен.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Update Blocked By Policy",
		Message: "The selected update is not compatible with the current server version.\n\n" +
			"What to do:\n" +
			"- Review `Service Health` and `Agent Diagnostics` for the policy details.\n" +
			"- Switch channels or use a rollback build if one is available.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func nameResolutionModeError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Неверный режим DNS",
			Message: "Ole не распознал выбранный режим разрешения имён для сети.\n\n" +
				"Что сделать:\n" +
				"- Используйте `DEFAULT`, `NETWORK_ONLY` или `DISABLED`.\n" +
				"- Затем повторите создание сети или применение политики.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Unsupported DNS Mode",
		Message: "Ole did not recognize the selected network name-resolution mode.\n\n" +
			"What to do:\n" +
			"- Use `DEFAULT`, `NETWORK_ONLY`, or `DISABLED`.\n" +
			"- Then try creating the network or applying the policy again.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func routingPolicyError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Неподдерживаемая routing policy",
			Message: "Ole не распознал выбранную политику маршрутизации сети.\n\n" +
				"Что сделать:\n" +
				"- Используй `SPLIT` или `FULL`.\n" +
				"- Затем повтори создание сети или применение policy.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Unsupported Routing Policy",
		Message: "Ole did not recognize the selected network routing policy.\n\n" +
			"What to do:\n" +
			"- Use `SPLIT` or `FULL`.\n" +
			"- Then try creating the network or applying the policy again.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func dnsLabelError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Некорректная DNS-метка",
			Message: "DNS-метка сети должна состоять только из букв, цифр и `-`.\n\n" +
				"Что сделать:\n" +
				"- Уберите пробелы и специальные символы.\n" +
				"- Не начинайте и не заканчивайте метку символом `-`.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Invalid DNS Label",
		Message: "The network DNS label must use only letters, digits, and `-`.\n\n" +
			"What to do:\n" +
			"- Remove spaces and special characters.\n" +
			"- Do not start or end the label with `-`.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func fileTransferPolicyRangeError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Некорректный лимит file transfer",
			Message: "Лимит файловых передач сети должен быть в диапазоне от 1 до 8388608 байт.\n\n" +
				"Что сделать:\n" +
				"- Укажите целое число в байтах.\n" +
				"- Или оставьте поле пустым, чтобы использовать стандартный лимит 8 MiB.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Invalid File Transfer Limit",
		Message: "The network file-transfer limit must be between 1 and 8388608 bytes.\n\n" +
			"What to do:\n" +
			"- Enter a whole number in bytes.\n" +
			"- Or leave the field blank to use the default 8 MiB limit.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func fileTransfersDisabledError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Файловые передачи отключены",
			Message: "В выбранной сети файловые передачи сейчас отключены политикой.\n\n" +
				"Что сделать:\n" +
				"- Включите `File Transfers` в настройках сети.\n" +
				"- Либо используйте обычные сообщения без payload.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "File Transfers Disabled",
		Message: "File transfers are currently disabled for the selected network.\n\n" +
			"What to do:\n" +
			"- Enable `File Transfers` in the network settings.\n" +
			"- Or use regular messages instead of file payload delivery.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func signInRequiredError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Нужна активная сессия",
			Message: "Для этого действия нужно сначала подключиться к Ole service.\n\n" +
				"Что сделать:\n" +
				"- Используйте `Login`, чтобы открыть новую сессию.\n" +
				"- Или используйте `Reconnect`, если у agent уже есть сохранённая сессия.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Active Session Required",
		Message: "This action requires an active Ole service session.\n\n" +
			"What to do:\n" +
			"- Use `Login` to start a new session.\n" +
			"- Or use `Reconnect` if the agent already has a saved session.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func reconnectUnavailableError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Нечего восстанавливать",
			Message: "Локальный agent не нашёл сохранённую сессию для `Reconnect`.\n\n" +
				"Что сделать:\n" +
				"- Выполните обычный `Login`.\n" +
				"- После успешного входа agent сможет восстанавливать эту сессию автоматически.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "No Saved Session",
		Message: "The local agent did not find a saved session for `Reconnect`.\n\n" +
			"What to do:\n" +
			"- Use a normal `Login`.\n" +
			"- After a successful sign-in, the agent will be able to restore that session later.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func selectionRequiredError(locale, kind, raw string) guiErrorMessage {
	if locale == "ru" {
		title := "Нужно сделать выбор"
		message := "Перед этим действием нужно выбрать нужный объект."
		switch kind {
		case "network":
			title = "Нужно выбрать сеть"
			message = "Сначала выберите сеть в списке `Networks`, а затем повторите действие."
		case "session":
			title = "Нужно выбрать сессию"
			message = "Сначала выберите нужную сессию в списке `Sessions`, а затем повторите действие."
		case "device":
			title = "Нужно выбрать устройство"
			message = "Сначала выберите устройство в списке `Trusted Devices`, а затем повторите действие."
		case "audit-preset":
			title = "Нужно выбрать audit preset"
			message = "Сначала выберите сохранённый audit preset в списке, а затем повторите действие."
		}
		return guiErrorMessage{
			Title:   title,
			Message: message + "\n\nТехническая деталь:\n" + raw,
		}
	}
	title := "Selection Required"
	message := "Select the required item and try again."
	switch kind {
	case "network":
		title = "Network Selection Required"
		message = "Select a network in the `Networks` list, then try again."
	case "session":
		title = "Session Selection Required"
		message = "Select a session in the `Sessions` list, then try again."
	case "device":
		title = "Device Selection Required"
		message = "Select a device in `Trusted Devices`, then try again."
	case "audit-preset":
		title = "Audit Preset Selection Required"
		message = "Select a saved audit preset, then try again."
	}
	return guiErrorMessage{
		Title:   title,
		Message: message + "\n\nTechnical detail:\n" + raw,
	}
}

func auditPresetNameRequiredError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title:   "Нужно имя для фильтра",
			Message: "Введите имя перед сохранением audit preset.\n\nТехническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title:   "Preset Name Required",
		Message: "Enter a name before saving the audit preset.\n\nTechnical detail:\n" + raw,
	}
}

func fingerprintUnavailableError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Fingerprint недоступен",
			Message: "У выбранного устройства сейчас нет fingerprint для копирования.\n\n" +
				"Что сделать:\n" +
				"- Обновите список устройств.\n" +
				"- Если это старое или частично зарегистрированное устройство, проверьте его состояние на сервере.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Fingerprint Unavailable",
		Message: "The selected device does not currently have a fingerprint to copy.\n\n" +
			"What to do:\n" +
			"- Refresh the device list.\n" +
			"- If this is an old or partially enrolled device, check its server-side state.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func deviceApprovalRequiredError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Требуется одобрение устройства",
			Message: "Эта сеть требует явного одобрения устройства перед регистрацией peer.\n\n" +
				"Что сделать:\n" +
				"- Выберите нужную сеть в `Networks`.\n" +
				"- Выберите устройство в `Trusted Devices`.\n" +
				"- Нажмите `Approve For Network`, затем повторите `Register Peer`.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Device Approval Required",
		Message: "This network requires an approved device before peer registration can continue.\n\n" +
			"What to do:\n" +
			"- Select the target network in `Networks`.\n" +
			"- Select the device in `Trusted Devices`.\n" +
			"- Press `Approve For Network`, then retry `Register Peer`.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func wholeNumberFieldError(locale, field, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title:   "Неверный формат числа",
			Message: fmt.Sprintf("Поле `%s` должно быть целым числом.\n\nТехническая деталь:\n%s", field, raw),
		}
	}
	return guiErrorMessage{
		Title:   "Invalid Number Format",
		Message: fmt.Sprintf("The `%s` field must be a whole number.\n\nTechnical detail:\n%s", field, raw),
	}
}

func adapterMTURangeError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Недопустимый MTU адаптера",
			Message: "Значение `Adapter MTU` должно быть в допустимом диапазоне для виртуального адаптера.\n\n" +
				"Что сделать:\n" +
				"- Используйте значение от 576 до 1500.\n" +
				"- Если не уверены, оставьте безопасное значение вроде 1360.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Invalid Adapter MTU",
		Message: "The `Adapter MTU` value must be within the valid virtual-adapter range.\n\n" +
			"What to do:\n" +
			"- Use a value between 576 and 1500.\n" +
			"- If unsure, keep a safe value such as 1360.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func endpointRequiredError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Нужен endpoint для rejoin",
			Message: "Для повторного входа в сеть agent нужен UDP endpoint.\n\n" +
				"Что сделать:\n" +
				"- Заполните поле `Endpoint`.\n" +
				"- Или сначала зарегистрируйте peer, чтобы agent запомнил endpoint автоматически.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Endpoint Required",
		Message: "The agent needs a UDP endpoint to rejoin this network.\n\n" +
			"What to do:\n" +
			"- Fill in the `Endpoint` field.\n" +
			"- Or register the peer first so the agent can remember the endpoint automatically.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func inviteError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Инвайт больше не действует",
			Message: "Этот invite уже истёк или у него закончились использования.\n\n" +
				"Что сделать:\n" +
				"- Попросите владельца сети создать новый invite.\n" +
				"- Затем повторите `Join By Invite`.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Invite Is No Longer Valid",
		Message: "This invite has expired or has no remaining uses.\n\n" +
			"What to do:\n" +
			"- Ask the network owner to create a new invite.\n" +
			"- Then try `Join By Invite` again.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func authorizationError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Доступ отклонён",
			Message: "Сервер отклонил это действие из-за состояния аккаунта, устройства или текущей сессии.\n\n" +
				"Что сделать:\n" +
				"- Проверьте `Service Health` и `Trusted Devices`.\n" +
				"- При необходимости войдите снова через `Login` или `Reconnect`.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Access Denied",
		Message: "The server rejected this action because of the account, device, or current session state.\n\n" +
			"What to do:\n" +
			"- Check `Service Health` and `Trusted Devices`.\n" +
			"- Sign in again with `Login` or `Reconnect` if needed.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func peerPathError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Peer-путь пока не готов",
			Message: "Ole ещё не видит готовый direct или relay путь до удалённого peer.\n\n" +
				"Что сделать:\n" +
				"- Убедитесь, что второй peer online и зарегистрировал endpoint.\n" +
				"- Обновите детали сети и проверьте `Connection Diagnostics`.\n" +
				"- Если direct недоступен, настройте relay server.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Peer Path Not Ready",
		Message: "Ole does not yet have a ready direct or relay path to the remote peer.\n\n" +
			"What to do:\n" +
			"- Make sure the other peer is online and has registered its endpoint.\n" +
			"- Refresh network details and check `Connection Diagnostics`.\n" +
			"- If direct stays unavailable, configure a relay server.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func relayQuotaError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Relay-лимит исчерпан",
			Message: "Текущий relay path достиг лимита пакетов или байтов.\n\n" +
				"Что сделать:\n" +
				"- Увеличьте relay quotas на сервере.\n" +
				"- Или дождитесь восстановления direct path.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Relay Quota Exhausted",
		Message: "The current relay path hit its packet or byte quota.\n\n" +
			"What to do:\n" +
			"- Increase relay quotas on the server.\n" +
			"- Or wait for the direct path to recover.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func notFoundError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Объект не найден",
			Message: "Ole не нашёл запрошенный объект.\n\n" +
				"Что сделать:\n" +
				"- Обновите список и проверьте, что объект всё ещё существует.\n" +
				"- Если это сеть, сессия или preset, выберите актуальный элемент заново.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Item Not Found",
		Message: "Ole could not find the requested item.\n\n" +
			"What to do:\n" +
			"- Refresh the list and confirm the item still exists.\n" +
			"- If this is a network, session, or preset, select the current item again.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func apiRequestError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Не удалось выполнить запрос",
			Message: "Локальный GUI получил неожиданный ответ от agent или server API.\n\n" +
				"Что сделать:\n" +
				"- Нажмите `Refresh Agent`.\n" +
				"- Если ошибка повторяется, выгрузите `Export Diagnostics` и проверьте совместимость версий.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Request Failed",
		Message: "The local GUI received an unexpected response from the agent or server API.\n\n" +
			"What to do:\n" +
			"- Press `Refresh Agent`.\n" +
			"- If it keeps failing, export diagnostics and check version compatibility.\n\n" +
			"Technical detail:\n" + raw,
	}
}

func genericGUIError(locale, raw string) guiErrorMessage {
	if locale == "ru" {
		return guiErrorMessage{
			Title: "Ошибка Ole",
			Message: "Ole не смог завершить это действие.\n\n" +
				"Что сделать:\n" +
				"- Повторите действие ещё раз.\n" +
				"- Если ошибка не исчезает, проверьте `Service Health` и выгрузите `Export Diagnostics`.\n\n" +
				"Техническая деталь:\n" + raw,
		}
	}
	return guiErrorMessage{
		Title: "Ole Error",
		Message: "Ole could not complete this action.\n\n" +
			"What to do:\n" +
			"- Try the action again.\n" +
			"- If it keeps failing, review `Service Health` and export diagnostics.\n\n" +
			"Technical detail:\n" + raw,
	}
}
