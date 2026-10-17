import { ButtonItem, DropdownItem, PanelSection, PanelSectionRow, TextField, ToggleField, staticClasses } from "@decky/ui";
import { callable, definePlugin } from "@decky/api";
import { useEffect, useState } from "react";

type Status = {
  state: string; message: string; error?: string; guard: boolean; desired: boolean; auto_connect: boolean;
  selected: string; preset: string; node_id?: string; addresses?: string[];
  profiles: { id: string; name: string; protocol: string }[];
  presets: Record<string, string>;
};
const rpc = callable<[method: string, params: Record<string, unknown>], unknown>("request");
type Action = (method: string, params?: Record<string, unknown>) => Promise<void>;

function Advanced({ status, busy, action }: { status?: Status; busy: boolean; action: Action }) {
  const [warpOpen, setWarpOpen] = useState(false);
  const [warpTerms, setWarpTerms] = useState(false);
  const [warpMode, setWarpMode] = useState("awg");
  const [warpEndpoint, setWarpEndpoint] = useState("");
  const selected = status?.profiles.find(p => p.id === status.selected);
  return <>
    <PanelSection title="Настройки">
      <PanelSectionRow><ToggleField label="Автоподключение"
        description="При загрузке Steam Deck подключать выбранный профиль. По умолчанию выключено."
        checked={status?.auto_connect ?? false} disabled={busy || !status}
        onChange={enabled => action("auto_connect", { enabled })} /></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !status?.desired || selected?.protocol === "zerotier"} onClick={() => action("probe")}>Проверить VPN</ButtonItem></PanelSectionRow>
      <PanelSectionRow><div style={{ fontSize: 12, lineHeight: 1.4, overflowWrap: "anywhere" }}>
        {status?.message}
        {selected && <div>Протокол: {selected.protocol}</div>}
        <div style={{ marginTop: 8 }}>Восстановление включённого VPN после сбоя или сна работает независимо от автоподключения.</div>
      </div></PanelSectionRow>
    </PanelSection>
    <PanelSection>
      <PanelSectionRow><ButtonItem layout="below" onClick={() => setWarpOpen(!warpOpen)}>
        {warpOpen ? "▾ Скрыть Cloudflare WARP" : "▸ Создать Cloudflare WARP"}
      </ButtonItem></PanelSectionRow>
      {warpOpen && <>
        <PanelSectionRow><div style={{ fontSize: 12, lineHeight: 1.4, overflowWrap: "anywhere" }}>WARP через wgcf. AmneziaWG с I1 и junk-пакетами; учётная запись сохраняется на Deck. Условия: https://www.cloudflare.com/application/terms/</div></PanelSectionRow>
        <PanelSectionRow><DropdownItem label="Режим WARP" disabled={busy} selectedOption={warpMode} rgOptions={[{ data: "awg", label: "AmneziaWG (с маскировкой)" }, { data: "wireguard", label: "WireGuard (обычный)" }]} onChange={o => setWarpMode(o.data)} /></PanelSectionRow>
        <PanelSectionRow><TextField label="Свой endpoint (необязательно)" value={warpEndpoint} disabled={busy} onChange={e => setWarpEndpoint(e.target.value)} /></PanelSectionRow>
        <PanelSectionRow><ToggleField label="Принимаю условия Cloudflare" checked={warpTerms} disabled={busy} onChange={setWarpTerms} /></PanelSectionRow>
        <PanelSectionRow><ButtonItem layout="below" disabled={busy || !warpTerms} onClick={() => action("warp_generate", { accept_terms: warpTerms, mode: warpMode, endpoint: warpEndpoint })}>Создать / восстановить WARP</ButtonItem></PanelSectionRow>
      </>}
    </PanelSection>
    <PanelSection><PanelSectionRow><div style={{ fontSize: 12, lineHeight: 1.4 }}>Профили, подписки, HWID и DNS настраиваются в Desktop Mode. Закрытие меню сохраняет соединение.</div></PanelSectionRow></PanelSection>
  </>;
}

function Content() {
  const [status, setStatus] = useState<Status>();
  const [error, setError] = useState("");
  const [serviceError, setServiceError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [advanced, setAdvanced] = useState(false);
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
        if (alive) setServiceError(String(e));
      } finally { pending = false; }
    };
    void refresh();
    const timer = setInterval(refresh, 4000);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  const action: Action = async (method, params = {}) => {
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await rpc(method, params);
      if (method === "probe" || method === "warp_generate") setNotice((result as { message: string }).message);
      if (method === "subscriptions_update") setNotice("Подписки обновлены");
      setStatus(await rpc("status", {}) as Status);
      setServiceError("");
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };
  const names: Record<string, string> = { disconnected: "Отключено", connecting: "Подключение…", running: "VPN включён", connected: "Подключено", authorizing: "Ожидание авторизации", error: "Ошибка" };
  const overlay = status?.profiles.find(p => p.id === status.selected)?.protocol === "zerotier";
  const reason = serviceError || error || status?.error || (status?.state === 'error' ? status.message : '');
  return <>
    <PanelSection>
      <PanelSectionRow><div style={{ fontSize: 13, lineHeight: 1.35, overflowWrap: "anywhere", padding: "4px 0" }}>
        <div>{busy ? "Выполняется…" : serviceError ? "Сервис недоступен" : status ? names[status.state] ?? status.state : "Ожидание сервиса…"}
          {status?.guard && !serviceError && <span style={{ color: "#9de0c4" }}> · защита включена</span>}
        </div>
        {reason && <div role="alert" style={{ color: "#ffad9e", marginTop: 6 }}>{reason}</div>}
        {status?.state === "authorizing" && <div style={{ marginTop: 6 }}>{status.message}</div>}
        {status?.node_id && <div>Node ID: {status.node_id}</div>}
        {status?.addresses?.length ? <div>{status.addresses.join(", ")}</div> : null}
        {notice && <div style={{ marginTop: 6 }}>{notice}</div>}
      </div></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !status || !!serviceError || (!status.profiles.length && !status.desired)} onClick={() => action(status?.desired ? "disconnect" : "connect")}>
        {status?.desired ? "Отключить" : "Подключить"}
      </ButtonItem></PanelSectionRow>
      {status && <>
        <PanelSectionRow><DropdownItem label="Профиль" disabled={busy || !!serviceError || !status.profiles.length} selectedOption={status.selected}
          rgOptions={status.profiles.map(p => ({ data: p.id, label: p.name }))}
          onChange={o => { if (o.data !== status.selected) void action("select", { profile_id: o.data }); }} /></PanelSectionRow>
        <PanelSectionRow><DropdownItem label="Маршрут" disabled={busy || !!serviceError || overlay} selectedOption={status.preset}
          rgOptions={Object.entries(status.presets).map(([data, label]) => ({ data, label }))}
          onChange={o => { if (o.data !== status.preset) void action("preset", { preset: o.data }); }} /></PanelSectionRow>
      </>}
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !status || !!serviceError} onClick={() => action("subscriptions_update")}>Обновить подписки</ButtonItem></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" onClick={() => setAdvanced(!advanced)}>
        {advanced ? "▾ Скрыть дополнительные настройки" : "▸ Дополнительно"}
      </ButtonItem></PanelSectionRow>
    </PanelSection>
    {advanced && <Advanced status={serviceError ? undefined : status} busy={busy} action={action} />}
  </>;
}

export default definePlugin(() => ({
  name: "Helmsman",
  titleView: <div className={staticClasses.Title} style={{ height: 24, lineHeight: "24px", fontSize: 18, whiteSpace: "nowrap" }}>Helmsman</div>,
  icon: <svg width="20" height="20" style={{ display: "block", width: 20, height: 20, flexShrink: 0 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="m16 7-3 7-6 3 3-7 6-3Z"/></svg>,
  content: <Content />,
}));
