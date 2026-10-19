import en from "../../helmsman/locales/en.json";
const catalogue: Record<string, string> = en;
const fragments = new RegExp(Object.keys(catalogue).sort((a, b) => b.length - a.length)
  .map(key => key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "g");
export const translator = (language: string) => (text: string) =>
  language === "en" ? catalogue[text] ?? text.replace(fragments, match => catalogue[match]) : text;
