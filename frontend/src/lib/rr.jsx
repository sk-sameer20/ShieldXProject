// Small bridge so the uploaded pages keep their react-router style API on top of TanStack Router.
import { createContext, forwardRef, useContext } from "react";
import { Link as TLink, Outlet as TOutlet, useRouterState } from "@tanstack/react-router";

const OutletCtx = createContext(undefined);

function split(to) {
  const [path, qs] = String(to).split("?");
  const search = qs ? Object.fromEntries(new URLSearchParams(qs)) : undefined;
  return { path, search };
}

export const Link = forwardRef(function Link({ to, ...rest }, ref) {
  const { path, search } = split(to);
  return <TLink ref={ref} to={path} search={search} {...rest} />;
});

export function NavLink({ to, end, className, ...rest }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname }).replace(/\/$/, "") || "/";
  const isActive = end ? pathname === to : pathname === to || pathname.startsWith(to + "/");
  const cls = typeof className === "function" ? className({ isActive }) : className;
  return <TLink to={to} className={cls} {...rest} />;
}

export function Outlet({ context }) {
  return (
    <OutletCtx.Provider value={context}>
      <TOutlet />
    </OutletCtx.Provider>
  );
}

export const useOutletContext = () => useContext(OutletCtx);

export function useLocation() {
  const loc = useRouterState({ select: (s) => s.location });
  return { pathname: loc.pathname.replace(/(.)\/$/, "$1"), search: loc.searchStr };
}

export function useSearchParams() {
  const searchStr = useRouterState({ select: (s) => s.location.searchStr });
  return [new URLSearchParams(searchStr)];
}
