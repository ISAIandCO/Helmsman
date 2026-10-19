import { ButtonItem, DropdownItem, PanelSection, PanelSectionRow, TextField, ToggleField, staticClasses } from "@decky/ui";
import { callable, definePlugin } from "@decky/api";
import { useEffect, useState } from "react";
import { translator } from "./i18n";

type Status = {
  state: string; message: string; error?: string; guard: boolean; desired: boolean; auto_connect: boolean;
  selected: string; preset: string; language: string; country: string; node_id?: string; addresses?: string[];
  profiles: { id: string; name: string; protocol: string }[];
  presets: Record<string, string>; countries: Record<string, string>; preset_descriptions: Record<string, string>;
  active_preset_name: string; active_preset_description: string;
};
const rpc = callable<[method: string, params: Record<string, unknown>], unknown>("request");
type Action = (method: string, params?: Record<string, unknown>) => Promise<void>;
type T = (text: string) => string;
const textStyle = { fontSize: 12, lineHeight: 1.4, overflowWrap: "anywhere" as const };

function Advanced({ status, busy, action, t }: { status?: Status; busy: boolean; action: Action; t: T }) {
  const [warpOpen, setWarpOpen] = useState(false);
  const [warpTerms, setWarpTerms] = useState(false);
  const [warpMode, setWarpMode] = useState("awg");
  const [warpEndpoint, setWarpEndpoint] = useState("");
  const selected = status?.profiles.find(p => p.id === status.selected);
  return <>
    <PanelSection title={t("Настройки")}>
      <PanelSectionRow><DropdownItem label={t("Язык интерфейса")} disabled={busy || !status} selectedOption={status?.language ?? "ru"}
        rgOptions={[{ data: "ru", label: "Русский" }, { data: "en", label: "English" }]}
        onChange={o => action("preferences", { language: o.data })} /></PanelSectionRow>
      <PanelSectionRow><DropdownItem label={t("Страна маршрутизации")} disabled={busy || !status} selectedOption={status?.country ?? "ru"}
        rgOptions={Object.entries(status?.countries ?? {}).map(([data, label]) => ({ data, label }))}
        onChange={o => action("preferences", { country: o.data })} /></PanelSectionRow>
      <PanelSectionRow><div style={textStyle}>{t("Страна меняет доступные пресеты, а не VPN-сервер. Примените выбранный маршрут отдельно.")}</div></PanelSectionRow>
      <PanelSectionRow><ToggleField label={t("Автоподключение")}
        description={t("При загрузке Steam Deck подключать выбранный профиль. По умолчанию выключено.")}
        checked={status?.auto_connect ?? false} disabled={busy || !status}
        onChange={enabled => action("auto_connect", { enabled })} /></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !status?.desired || selected?.protocol === "zerotier"} onClick={() => action("probe")}>{t("Проверить VPN")}</ButtonItem></PanelSectionRow>
      <PanelSectionRow><div style={textStyle}>
        {status?.message}
        {selected && <div>{t("Протокол: ")}{selected.protocol}</div>}
        <div style={{ marginTop: 8 }}>{t("Восстановление включённого VPN после сбоя или сна работает независимо от автоподключения.")}</div>
      </div></PanelSectionRow>
    </PanelSection>
    <PanelSection>
      <PanelSectionRow><ButtonItem layout="below" onClick={() => setWarpOpen(!warpOpen)}>
        {warpOpen ? t("▾ Скрыть Cloudflare WARP") : t("▸ Создать Cloudflare WARP")}
      </ButtonItem></PanelSectionRow>
      {warpOpen && <>
        <PanelSectionRow><div style={textStyle}>{t("WARP через wgcf. AmneziaWG с I1 и junk-пакетами; учётная запись сохраняется на Deck. Условия: https://www.cloudflare.com/application/terms/")}</div></PanelSectionRow>
        <PanelSectionRow><DropdownItem label={t("Режим WARP")} disabled={busy} selectedOption={warpMode} rgOptions={[{ data: "awg", label: t("AmneziaWG (с маскировкой)") }, { data: "wireguard", label: t("WireGuard (обычный)") }]} onChange={o => setWarpMode(o.data)} /></PanelSectionRow>
        <PanelSectionRow><TextField label={t("Свой endpoint (необязательно)")} value={warpEndpoint} disabled={busy} onChange={e => setWarpEndpoint(e.target.value)} /></PanelSectionRow>
        <PanelSectionRow><ToggleField label={t("Принимаю условия Cloudflare")} checked={warpTerms} disabled={busy} onChange={setWarpTerms} /></PanelSectionRow>
        <PanelSectionRow><ButtonItem layout="below" disabled={busy || !warpTerms} onClick={() => action("warp_generate", { accept_terms: warpTerms, mode: warpMode, endpoint: warpEndpoint })}>{t("Создать / восстановить WARP")}</ButtonItem></PanelSectionRow>
      </>}
    </PanelSection>
    <PanelSection><PanelSectionRow><div style={textStyle}>{t("Профили, подписки, HWID и DNS настраиваются в Desktop Mode. Закрытие меню сохраняет соединение.")}</div></PanelSectionRow></PanelSection>
  </>;
}

function Content() {
  const [status, setStatus] = useState<Status>();
  const [error, setError] = useState("");
  const [serviceError, setServiceError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [preset, setPreset] = useState("");
  const [fallbackLanguage, setFallbackLanguage] = useState(() => localStorage.getItem("helmsman.language") ?? "ru");
  const t = translator(status?.language ?? fallbackLanguage);
  useEffect(() => {
    let alive = true;
    let pending = false;
    const refresh = async () => {
      if (pending) return;
      pending = true;
      try {
        const state = await rpc("status", {}) as Status;
        if (alive) { setStatus(state); setServiceError(""); }
      } catch (e) {
        if (alive) setServiceError(t(String(e)));
      } finally { pending = false; }
    };
    void refresh();
    const timer = setInterval(refresh, 4000);
    return () => { alive = false; clearInterval(timer); };
  }, [status?.language]);
  useEffect(() => {
    if (status) {
      setPreset(Object.prototype.hasOwnProperty.call(status.presets, status.preset) ? status.preset : "");
      localStorage.setItem("helmsman.language", status.language);
      setFallbackLanguage(status.language);
    }
  }, [status?.language, status?.country, status?.preset]);

  const action: Action = async (method, params = {}) => {
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await rpc(method, params);
      if (method === "probe" || method === "warp_generate") setNotice((result as { message: string }).message);
      if (method === "subscriptions_update") setNotice(t("Подписки обновлены"));
      setStatus(await rpc("status", {}) as Status);
      setServiceError("");
    } catch (e) { setError(t(String(e))); }
    finally { setBusy(false); }
  };
  const names: Record<string, string> = { disconnected: t("Отключено"), connecting: t("Подключение…"), running: t("VPN включён"), connected: t("Подключено"), authorizing: t("Ожидание авторизации"), error: t("Ошибка") };
  const overlay = status?.profiles.find(p => p.id === status.selected)?.protocol === "zerotier";
  const reason = serviceError || error || status?.error || (status?.state === 'error' ? status.message : '');
  return <>
    <PanelSection>
      <PanelSectionRow><div style={{ ...textStyle, fontSize: 13, padding: "4px 0" }}>
        <div>{busy ? t("Выполняется…") : serviceError ? t("Сервис недоступен") : status ? names[status.state] ?? status.state : t("Ожидание сервиса…")}
          {status?.guard && !serviceError && <span style={{ color: "#9de0c4" }}>{t(" · защита включена")}</span>}
        </div>
        {reason && <div role="alert" style={{ color: "#ffad9e", marginTop: 6 }}>{reason}</div>}
        {status?.state === "authorizing" && <div style={{ marginTop: 6 }}>{status.message}</div>}
        {status?.node_id && <div>Node ID: {status.node_id}</div>}
        {status?.addresses?.length ? <div>{status.addresses.join(", ")}</div> : null}
        {notice && <div style={{ marginTop: 6 }}>{notice}</div>}
      </div></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !status || !!serviceError || (!status.profiles.length && !status.desired)} onClick={() => action(status?.desired ? "disconnect" : "connect")}>
        {status?.desired ? t("Отключить") : t("Подключить")}
      </ButtonItem></PanelSectionRow>
      {status && <>
        <PanelSectionRow><DropdownItem label={t("Профиль")} disabled={busy || !!serviceError || !status.profiles.length} selectedOption={status.selected}
          rgOptions={status.profiles.map(p => ({ data: p.id, label: p.name }))}
          onChange={o => { if (o.data !== status.selected) void action("select", { profile_id: o.data }); }} /></PanelSectionRow>
        <PanelSectionRow><div style={textStyle}>{t("Действует: ")}{status.active_preset_name}</div></PanelSectionRow>
        <PanelSectionRow><DropdownItem label={t("Маршрут")} disabled={busy || !!serviceError || overlay} selectedOption={preset}
          rgOptions={[...(!preset ? [{ data: "", label: t("Выберите маршрут") }] : []), ...Object.entries(status.presets).map(([data, label]) => ({ data, label }))]}
          onChange={o => setPreset(o.data)} /></PanelSectionRow>
        <PanelSectionRow><div style={textStyle}>{status.preset_descriptions[preset] ?? status.active_preset_description}</div></PanelSectionRow>
        <PanelSectionRow><ButtonItem layout="below" disabled={busy || !!serviceError || overlay || !preset} onClick={() => action("preset", { preset })}>{t("Применить маршрут")}</ButtonItem></PanelSectionRow>
      </>}
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !status || !!serviceError} onClick={() => action("subscriptions_update")}>{t("Обновить подписки")}</ButtonItem></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" onClick={() => setAdvanced(!advanced)}>
        {advanced ? t("▾ Скрыть дополнительные настройки") : t("▸ Дополнительно")}
      </ButtonItem></PanelSectionRow>
    </PanelSection>
    {advanced && <Advanced status={serviceError ? undefined : status} busy={busy} action={action} t={t} />}
  </>;
}

export default definePlugin(() => ({
  name: "Helmsman",
  titleView: <div className={staticClasses.Title} style={{ height: 24, lineHeight: "24px", fontSize: 18, whiteSpace: "nowrap" }}>Helmsman</div>,
  icon: <svg width="20" height="20" style={{ display: "block", width: 20, height: 20, flexShrink: 0 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="m16 7-3 7-6 3 3-7 6-3Z"/></svg>,
  content: <Content />,
}));
