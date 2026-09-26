import { useId, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { CheckIcon, ChevronRightIcon } from "./icons";

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

// Select-only combobox: DOM focus stays on the trigger, including in a modal.
// Highlighting is provisional; Enter, Space or a pointer selection commits it.
export function ThemedSelect({ id, label, value, options, onChange, disabled = false, autoFocus = false }: {
  id?: string;
  label: string;
  value: string;
  options: readonly SelectOption[];
  onChange: (value: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
}) {
  const listId = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const search = useRef({ text: "", at: 0 });
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [position, setPosition] = useState({ left: 0, top: 0, width: 180, maxHeight: 240, above: false });
  const selected = options.findIndex((option) => option.value === value);
  const enabled = options.map((option, index) => option.disabled ? -1 : index).filter((index) => index >= 0);

  const reveal = (index = selected >= 0 && !options[selected].disabled ? selected : enabled[0]) => {
    if (disabled || index === undefined) return;
    setActive(index);
    search.current = { text: "", at: 0 };
    setOpen(true);
  };
  const choose = (index: number) => {
    if (!options[index] || options[index].disabled) return;
    setOpen(false);
    if (options[index].value !== value) onChange(options[index].value);
  };

  useLayoutEffect(() => {
    if (!open) return;
    const button = trigger.current;
    if (!button || disabled || !button.getClientRects().length) { setOpen(false); return; }
    const rect = button.getBoundingClientRect();
    const width = Math.min(Math.max(rect.width, 180), window.innerWidth - 16);
    const below = window.innerHeight - rect.bottom - 14;
    const aboveSpace = rect.top - 14;
    const desired = Math.min(options.length * 44 + 10, 240);
    const above = below < desired && aboveSpace > below;
    const height = Math.min(desired, Math.max(44, above ? aboveSpace : below));
    setPosition({ left: Math.max(8, Math.min(rect.left, window.innerWidth - width - 8)),
      top: above ? rect.top - height - 6 : rect.bottom + 6, width, maxHeight: height, above });

    const outside = (event: Event) => {
      const target = event.target as Node | null;
      if (!button.contains(target) && !list.current?.contains(target)) setOpen(false);
    };
    const scroll = (event: Event) => {
      if (list.current?.contains(event.target as Node | null)) return;
      // A pointer click may finish a preceding scroll-into-view after opening.
      // Dismiss when the anchor actually moves, not on that stale scroll event.
      const current = button.getBoundingClientRect();
      if (Math.abs(current.top - rect.top) > 1 || Math.abs(current.left - rect.left) > 1) setOpen(false);
    };
    const resize = () => setOpen(false);
    document.addEventListener("pointerdown", outside, true);
    document.addEventListener("focusin", outside);
    document.addEventListener("scroll", scroll, true);
    window.addEventListener("resize", resize);
    return () => {
      document.removeEventListener("pointerdown", outside, true);
      document.removeEventListener("focusin", outside);
      document.removeEventListener("scroll", scroll, true);
      window.removeEventListener("resize", resize);
    };
  }, [open, disabled, options.length]);

  useLayoutEffect(() => {
    if (open) list.current?.children[active]?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const key = event.key;
    if (key === "Tab") { setOpen(false); return; }
    if (key === "Escape" && open) {
      event.preventDefault(); event.stopPropagation(); setOpen(false); return;
    }
    if (key === "Enter" || key === " ") {
      event.preventDefault();
      if (open) choose(active); else reveal();
      return;
    }
    if (enabled.length === 0) return;
    if (key === "ArrowDown" || key === "ArrowUp" || key === "Home" || key === "End") {
      event.preventDefault();
      if (event.altKey && key === "ArrowUp") { setOpen(false); return; }
      if (key === "Home") { if (open) setActive(enabled[0]); else reveal(enabled[0]); }
      else if (key === "End") { if (open) setActive(enabled[enabled.length - 1]); else reveal(enabled[enabled.length - 1]); }
      else if (!open) reveal();
      else {
        const next = Math.max(0, Math.min(enabled.length - 1, enabled.indexOf(active) + (key === "ArrowDown" ? 1 : -1)));
        setActive(enabled[next]);
      }
      return;
    }
    if (key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      const character = key.toLocaleLowerCase("ru-RU");
      const previous = Date.now() - search.current.at < 700 ? search.current.text : "";
      const query = previous === character ? character : previous + character;
      search.current = { text: query, at: Date.now() };
      const start = open ? active : selected;
      const indices = [...enabled.filter((index) => index > start), ...enabled.filter((index) => index <= start)];
      const match = indices.find((index) => options[index].label.toLocaleLowerCase("ru-RU").startsWith(query));
      if (match !== undefined) { setActive(match); setOpen(true); }
    }
  };

  return <>
    <button id={id} ref={trigger} type="button" role="combobox" className="themed-select"
      aria-label={label} aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? listId : undefined}
      aria-activedescendant={open ? `${listId}-${active}` : undefined} data-value={value}
      data-autofocus={autoFocus || undefined} disabled={disabled} onKeyDown={onKeyDown}
      onClick={() => open ? setOpen(false) : reveal()}>
      <span>{options[selected]?.label ?? value}</span><ChevronRightIcon size={16} />
    </button>
    {open ? createPortal(<div id={listId} ref={list} role="listbox" aria-label={label}
      className="select-popover" data-above={position.above || undefined}
      style={{ left: position.left, top: position.top, width: position.width, maxHeight: position.maxHeight }}>
      {options.map((option, index) => <div key={option.value} id={`${listId}-${index}`} role="option"
        aria-selected={option.value === value} aria-disabled={option.disabled || undefined}
        className="select-option" data-active={active === index || undefined} data-value={option.value}
        onPointerMove={() => { if (!option.disabled) setActive(index); }}
        onPointerDown={(event) => event.preventDefault()} onClick={() => choose(index)}>
        <span>{option.label}</span>{option.value === value ? <CheckIcon size={16} /> : null}
      </div>)}
    </div>, trigger.current?.closest("[role='dialog']") ?? document.body) : null}
  </>;
}
