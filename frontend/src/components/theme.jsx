import { createContext, useCallback, useContext, useEffect, useState } from "react";

const KEY = "shieldx-theme";
const ThemeCtx = createContext({ theme: "light", toggle: () => {} });

function read() {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    /* private mode or blocked storage — fall through to the default */
  }
  return "light";
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("light");
  useEffect(() => setTheme(read()), []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* preference just won't persist */
    }
  }, [theme]);

  const toggle = useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), []);

  return <ThemeCtx.Provider value={{ theme, toggle }}>{children}</ThemeCtx.Provider>;
}

export const useTheme = () => useContext(ThemeCtx);
