import { ButtonItem, DropdownItem, PanelSection, PanelSectionRow, TextField, ToggleField, staticClasses } from "@decky/ui";
import { callable, definePlugin } from "@decky/api";
import { useEffect, useState } from "react";

type Status = {
  state: string; message: string; error?: string; guard: boolean; desired: boolean;
  selected: string; preset: string; node_id?: string; addresses?: string[];
  profiles: { id: string; name: string; protocol: string }[];
  presets: Record<string, string>;
};
const rpc = callable<[method: string, params: Record<string, unknown>], unknown>("request");

function Content() {
  const [status, setStatus] = useState<Status>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [probe, setProbe] = useState("");
  const [warpTerms, setWarpTerms] = useState(false);
  const [warpMode, setWarpMode] = useState("awg");
  const [warpEndpoint, setWarpEndpoint] = useState("");
  useEffect(() => {
    let alive = true;
    let pending = false;
    const refresh = async () => {
      if (pending) return;
      pending = true;
      try {
        const state = await rpc("status", {}) as Status;
        if (alive) setStatus(state);
      } catch (e) {
        if (alive) setError(String(e));
      } finally { pending = false; }
    };
    void refresh();
    const timer = setInterval(refresh, 4000);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  const action = async (method: string, params: Record<string, unknown> = {}) => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await rpc(method, params);
      if (method === "probe" || method === "warp_generate") setProbe((result as { message: string }).message);
      setStatus(await rpc("status", {}) as Status);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };
  const names: Record<string, string> = { disconnected: "Отключено", connecting: "Подключение…", running: "VPN включён", connected: "Подключено", authorizing: "Ожидание авторизации", error: "Ошибка" };
  const overlay = status?.profiles.find(p => p.id === status.selected)?.protocol === "zerotier";
  return <>
    <PanelSection title={status ? names[status.state] ?? status.state : "Helmsman"}>
      <PanelSectionRow><div style={{ fontSize: 14, lineHeight: 1.45, overflowWrap: "anywhere" }}>
        {busy ? "Выполняется…" : status?.message ?? "Ожидание сервиса…"}
        {status?.guard && <p>Защита от прямого выхода включена</p>}
        {status?.node_id && <p>Node ID: {status.node_id}</p>}
        {status?.addresses?.length ? <p>{status.addresses.join(", ")}</p> : null}
        {(error || status?.error) && <p style={{ color: "#ffad9e" }}>{error || status?.error}</p>}
        {probe && <p>{probe}</p>}
      </div></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !status?.profiles.length} onClick={() => action(status?.desired ? "disconnect" : "connect")}>
        {status?.desired ? "Отключить" : "Подключить"}
      </ButtonItem></PanelSectionRow>
      {status && <>
        <PanelSectionRow><DropdownItem label="Подключение" disabled={busy} selectedOption={status.selected}
          rgOptions={status.profiles.map(p => ({ data: p.id, label: `${p.name} · ${p.protocol}` }))}
          onChange={o => action("select", { profile_id: o.data })} /></PanelSectionRow>
        <PanelSectionRow><DropdownItem label="Сценарий VPN" disabled={busy || overlay} selectedOption={status.preset}
          rgOptions={Object.entries(status.presets).map(([data, label]) => ({ data, label }))}
          onChange={o => action("preset", { preset: o.data })} /></PanelSectionRow>
      </>}
    </PanelSection>
    <PanelSection title="Cloudflare WARP">
      <PanelSectionRow><div style={{ fontSize: 12, overflowWrap: "anywhere" }}>WARP через wgcf. По умолчанию — AmneziaWG с I1 и junk-пакетами. Учётная запись сохраняется на Deck и используется повторно. Условия: https://www.cloudflare.com/application/terms/</div></PanelSectionRow>
      <PanelSectionRow><DropdownItem label="Режим WARP" disabled={busy} selectedOption={warpMode} rgOptions={[{data: "awg", label: "AmneziaWG (с маскировкой)"}, {data: "wireguard", label: "WireGuard (обычный)"}]} onChange={o => setWarpMode(o.data)} /></PanelSectionRow>
      <PanelSectionRow><TextField label="Свой endpoint (необязательно)" value={warpEndpoint} disabled={busy} onChange={e => setWarpEndpoint(e.target.value)} /></PanelSectionRow>
      <PanelSectionRow><ToggleField label="Принимаю условия Cloudflare" checked={warpTerms} disabled={busy} onChange={setWarpTerms} /></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !warpTerms} onClick={() => action("warp_generate", { accept_terms: warpTerms, mode: warpMode, endpoint: warpEndpoint })}>Создать / восстановить WARP</ButtonItem></PanelSectionRow>
    </PanelSection>
    <PanelSection title="Обслуживание">
      <PanelSectionRow><ButtonItem layout="below" disabled={busy} onClick={() => action("subscriptions_update")}>Обновить подписки</ButtonItem></PanelSectionRow>
      <PanelSectionRow><ButtonItem layout="below" disabled={busy || !status?.desired || overlay} onClick={() => action("probe")}>Проверить VPN</ButtonItem></PanelSectionRow>
      <PanelSectionRow><div style={{ fontSize: 12 }}>Полная настройка — в Helmsman в Desktop Mode. Закрытие меню сохраняет соединение.</div></PanelSectionRow>
    </PanelSection>
  </>;
}

export default definePlugin(() => ({
  name: "Helmsman",
  titleView: <div className={staticClasses.Title}>Helmsman</div>,
  icon: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/><path d="M12 1v8m0 6v8M1 12h8m6 0h8M4 4l6 6m4 4 6 6M4 20l6-6m4-4 6-6"/></svg>,
  content: <Content />,
}));
