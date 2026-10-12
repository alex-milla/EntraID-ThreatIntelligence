# Guía de implementación de la interfaz — FinSec TI Dashboard

> Documento de referencia para replicar el sistema de diseño y la capa visual de la web en otro proyecto. Se describen paletas, tipografías, espaciados, comportamientos de menús, componentes recurrentes y microinteracciones. No se enumeran rutas ni textos de menú concretos; solo el sistema visual que los envuelve.

## 1. Stack visual

| Capa | Tecnología |
|---|---|
| Estilos | Tailwind CSS 3.4 (utility-first, `darkMode: 'class'`) |
| Tokens | Variables CSS en `styles/tokens.css` + `tailwind.config.js` |
| Tipografía | Inter (sans) + JetBrains Mono (mono), vía Google Fonts |
| Iconografía | `lucide-react` (stroke 1.5, tamaños fijos por contexto) |
| Gráficos | `recharts` (line, bar, pie) |
| Mapa | `react-leaflet` + OpenStreetMap tiles |
| Estado tema | Zustand (`themeStore`) con `localStorage` |
| i18n | `react-i18next` (todos los textos vienen de `locales/es|en.json`) |

## 2. Paleta de color

### 2.1 Marca — naranja pastel (escala 50–950)

La marca es un naranja "soft/alerta" basado en la escala orange de Tailwind, usada como acento y como único color de acción primaria.

| Token | Hex | Uso típico |
|---|---|---|
| `brand-50`  | `#fff7ed` | Fondo de item de menú activo (light) |
| `brand-100` | `#ffedd5` | Borde hover de tarjetas (light), fondo chip rol |
| `brand-200` | `#fed7aa` | Spinner (anillo exterior) |
| `brand-300` | `#fdba74` | Borde hover de tarjetas (light), segundo tono de líneas en gráficos |
| `brand-400` | `#fb923c` | Línea secundaria en gráficos, `fillColor` mapa |
| `brand-500` | `#f97316` | **Acento principal**: botones, foco, iconos destacados, logo, serie 1 de gráficos |
| `brand-600` | `#ea580c` | Hover de botones primarios |
| `brand-700` | `#c2410c` | Texto de item activo (light), borde hover dark |
| `brand-900` | `#7c2d12` | Fondo chip rol (dark) |
| `brand-950` | `#431407` | Fondo de item de menú activo (dark) |

La marca **nunca** se mezcla con otra saturación: el naranja es el único color de marca y todo lo "destacado" (foco, activo, CTA, logo) lo usa.

### 2.2 Superficies (claro / oscuro)

El tema dual se resuelve con la clase `.dark` en `<html>` (estrategia `class` de Tailwind). Cada superficie se define en dos tokens:

| Token | Claro | Oscuro | Rol |
|---|---|---|---|
| `surface` | `#ffffff` | `#0f172a` (slate-900) | Tarjetas, header, sidebar, diálogos |
| `muted`  | `#f1f5f9` (slate-100) | `#1e293b` (slate-800) | Hover de botones/iconos, paneles internos, cabeceras de tabla, cuadros de stats internos |

Fondo de página: `bg-gray-50` (light) / `bg-gray-900` (dark) — un gris ligeramente distinto a `surface` para que las tarjetas floten.

Texto:
- Primario `text-gray-900 dark:text-white`
- Secundario `text-gray-500 dark:text-gray-400`
- Terciario/fechas `text-gray-400`
- Etiquetas en formularios `text-gray-700 dark:text-gray-300`

Bordes: `border-gray-200 dark:border-gray-700` (default) y `border-gray-100 dark:border-gray-700/50` (separadores ligeros en tablas).

### 2.3 Color semántico (estados)

Se reutiliza la paleta estándar de Tailwind **solo para semántica**, nunca para marca. Patrón uniforme: `bg-{c}-100 dark:bg-{c}-900/30` + `text-{c}-700 dark:text-{c}-300`.

| Significado | Color base | Ejemplos |
|---|---|---|
| Crítico / activo / KEV | red | "Active", KEV badge, CVSS ≥ 9, errores de formulario |
| Alto / advertencia | orange (Tailwind, no marca) | CVSS 7–8.9, severidad alta |
| Medio / aviso | yellow | CVSS 4–6.9, severidad media |
| Bajo / OK / financiero | green | "Financial", CVSS < 4, severidad baja, "completed", activo |
| Informativo / progreso | blue | banner de "sincronizando en segundo plano" |
| Neutral | gray | placeholder, estados vacíos, "—" |

Los semáforos de badges numéricos (CVSS, EPSS, severidad) comparten los mismos umbrales visuales, de modo que el ojo asocia color → nivel de riesgo en toda la app.

## 3. Tipografía

- Sans: **Inter** con pesos 300/400/500/600/700 cargados desde Google Fonts (`preconnect` + `display=swap`).
- Mono: **JetBrains Mono** pesos 400/500, reservado para identificadores técnicos (CVE IDs, nombres de grupo, versiones, logs, valores de configuración).
- `body` con `antialiased`. `html` fija `font-family: Inter`.
- Escala de tamaños (todo en Tailwind, no se customiza):
  - Página/título de detalle `text-2xl font-bold`
  - Título de sección de página `text-xl font-bold`
  - Subtítulo de tarjeta `text-lg font-semibold`
  - Etiqueta de tarjeta `text-sm font-semibold`
  - Texto base `text-sm`
  - Fechas/meta `text-xs`
  - Cabeceras de grupo en sidebar `text-xs font-semibold uppercase tracking-wider`
- `line-clamp-2` para descripciones largas en tarjetas.

## 4. Layout y estructura general

### 4.1 Shell

`AppLayout` = flex horizontal a `min-h-screen`:

```
┌──────────┬─────────────────────────────┐
│ Sidebar  │ Header fijo (h-16)          │
│ w-64     ├─────────────────────────────┤
│          │ <main> p-6 overflow-auto     │
│          │   <Outlet/>  (página)        │
└──────────┴─────────────────────────────┘
```

- Sidebar **fija a la izquierda, 256px (`w-64`)**, visible desde `lg` hacia arriba (`lg:translate-x-0 lg:static`).
- Por debajo de `lg` el sidebar es un drawer: `fixed`, translate-x `-full` / `0`, con overlay `bg-black/50 z-20` que cierra al click.
- En móvil aparece una barra superior propia (`h-16`, `lg:hidden`) con botón hamburguesa (`Menu`) + nombre de producto, porque el sidebar está oculto.
- Header: `h-16`, `border-b`, `px-6`, `flex justify-between` — título a la izquierda, acciones (theme toggle + menú de usuario) a la derecha.
- `main`: `flex-1 p-6 overflow-auto`. El `min-w-0` en el contenedor central evita overflow horizontal con textos largos.

### 4.2 Sidebar — patrones de menú

- Cabecera del sidebar `h-16 px-6 border-b` con un logo cuadrado `w-8 h-8 rounded-lg bg-brand-500` (icono blanco) + nombre en `font-bold text-lg`.
- `nav` con `p-4 space-y-1 overflow-y-auto`.
- Enlaces agrupados en **tres bloques separados por etiquetas-sección** en `text-xs font-semibold text-gray-400 uppercase tracking-wider px-3 mb-1` (con `mt-4` entre bloques). Esto es la guía visual de "categorías de menú".
- Cada ítem es un `NavLink` con `end` en la ruta raíz, `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors`.
- Estado activo: `bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300` (fondo brand muy claro + texto brand oscuro).
- Estado inactivo: `text-gray-600 dark:text-gray-400` + hover `bg-muted-light dark:bg-muted-dark`.
- Icono siempre a `size={18}` a la izquierda del texto.
- El `onClick` del ítem cierra el drawer en móvil.

### 4.3 Header — menú de usuario

- Botón usuario: `flex items-center gap-2 text-sm` con icono `User size={16}`, nombre y un **chip de rol** `px-2 py-0.5 text-xs rounded-full bg-brand-100 dark:bg-brand-900 text-brand-700 dark:text-brand-300`.
- Menú desplegable: `absolute right-0 top-full mt-2 w-48`, tarjeta `bg-white dark:bg-surface-dark rounded-lg shadow-lg border py-1 z-20`, con un overlay `fixed inset-0 z-10` transparente para cerrar al click fuera.
- Ítems del menú: `w-full flex items-center gap-2 px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors`. Separador con `border-t my-1`. Acción peligrosa (logout) en `text-red-600 hover:bg-red-50 dark:hover:bg-red-950`.
- Banner de "debe cambiar contraseña" (cuando aplica): franja `bg-amber-50 dark:bg-amber-950 border-b border-amber-200/900 px-6 py-2` con icono `AlertTriangle size={16}` + enlace subrayado.

### 4.4 Theme toggle

- Botón `p-2 rounded-lg hover:bg-muted-light dark:hover:bg-muted-dark transition-colors` con icono `Sun`/`Moon`/`Monitor` a `size={18}`.
- Cicla `light → dark → auto → light`. El modo `auto` sigue `prefers-color-scheme` y reacciona en vivo a cambios del SO (listener en `themeStore`).
- Persistencia en `localStorage` ('theme'). Al cargar el módulo se aplica el tema antes del primer render (sin flash).
- La transición entre temas es global vía `.transition-theme` (ver §10).

## 5. Tarjetas (componente base recurrente)

Es el bloque de construcción dominante. Patrón casi idéntico en KPIs, listas, charts, formularios y diálogos:

```
<div class="bg-white dark:bg-surface-dark
            rounded-xl border border-gray-200 dark:border-gray-700
            {p-4 | p-5 | p-6}">
```

- Esquinas: `rounded-xl` (0.75rem) para tarjetas, `rounded-lg` (0.5rem) para inputs/botones/pequeños, `rounded-md` para tabs, `rounded-full` para badges de estado y avatar de rol.
- Bordes siempre `1px` de `gray-200/gray-700`; sin sombra por defecto.
- **Hover de tarjetas clicables** (VictimCard, GroupCard, CveCard):
  `hover:shadow-md hover:border-brand-300 dark:hover:border-brand-700 transition-all` + `cursor-pointer`.
- Padding escalonado por densidad: `p-4` (tarjetas de lista/chart compacto), `p-5` (KPI), `p-6` (detalle, formularios, diálogo, secciones admin).

### Estructura interna de una tarjeta de entidad

1. Fila superior `flex items-start justify-between gap-3` — bloque de texto a la izquierda (`min-w-0 flex-1`, con `truncate` en el título) y acción/media a la derecha (`shrink-0`).
2. Bajo el título, fila de badges `flex items-center gap-2 mt-1 flex-wrap`.
3. Descripción opcional `mt-2 text-sm text-gray-500 line-clamp-2`.
4. Pie `mt-3 flex items-center justify-between text-xs text-gray-400` con icono pequeño (`size={12}`) + chips.

### KPI card

- Contenido: etiqueta `text-sm text-gray-500` + icono brand `text-brand-500` a `size={18}` arriba; abajo valor `text-3xl font-bold` + variación `text-xs font-medium` con `TrendingUp/Down` (`text-green-600`/`text-red-600`).
- Grid responsive: `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4`.

## 6. Badges y chips

Convención común: `inline-flex items-center {gap-1} px-{2|2.5} py-0.5 text-xs font-{medium|bold}`.

| Tipo | Forma | Color |
|---|---|---|
| Estado (activo/KEV/severidad) | `rounded-full` | semántico red/orange/yellow/green |
| Sector | `rounded` | brand-50/950 + brand-700/300 |
| Rol | `rounded-full` | brand-100/900 + brand-700/300 |
| Financial | `rounded` | green-100/900-30 + green-700/300 |
| Grupo (en tarjeta víctima) | `rounded` | gray-100/800 + gray-600/300 |
| CVSS / EPSS | `rounded` | semántico por umbral, `font-bold` |
| País | sin fondo | emoji bandera (codepoint 127397+) + texto `text-gray-600/400` |

Valores nulos se renderizan como `—` en `text-xs text-gray-400`, no como badge vacío.

## 7. Formularios e inputs

- **Label**: `block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1`. En filtros compactos baja a `text-xs text-gray-500`.
- **Input/Select** estándar:
  `w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent`.
  En dark, el fondo del input es `gray-800` (no `surface-dark`) para diferenciarlo del contenedor.
- **Foco**: anillo brand (`focus:ring-2 focus:ring-brand-500`) + border transparente. Es el único foco visual de la app y siempre es brand-500.
- **SearchInput**: input con icono `Search` a la izquierda (`absolute left-3 top-1/2 -translate-y-1/2 text-gray-400`), padding `pl-9 pr-8`, y botón `X` a la derecha cuando hay valor.
- **Toggle segmentado** (FinancialToggle): contenedor `inline-flex rounded-lg border bg-surface overflow-hidden`; cada botón `px-4 py-2 text-sm font-medium transition-colors`, activo `bg-brand-500 text-white`, inactivo `text-gray-600/400 hover:bg-gray-50/dark:hover:bg-muted-dark`.
- **Botón primario**: `bg-brand-500 hover:bg-brand-600 text-white font-medium rounded-lg transition-colors`. States: `disabled:opacity-50 disabled:cursor-not-allowed`.
- **Botón secundario**: `border border-gray-200/700 ... hover:bg-gray-50/dark:hover:bg-muted-dark`.
- **Botón de acción de tabla** (activar/desactivar): icono `p-1.5 rounded-lg` con hover semántico green/red.

## 8. Tablas

- Contenedor tarjeta con `overflow-hidden` (para respetar el `rounded-xl`).
- `thead tr`: `border-b bg-gray-50 dark:bg-gray-800`, celdas `text-left px-4 py-3 font-medium text-gray-600/400`.
- `tbody tr`: `border-b border-gray-100 dark:border-gray-700/50 hover:bg-gray-50 dark:hover:bg-gray-800/50`.
- Celdas: `px-4 py-3`. Texto principal `text-gray-900 dark:text-white`, secundario `text-gray-500`.
- Iconos de estado `CheckCircle/XCircle` a `size={16}` en green-500/red-500.
- Selects inline de celda: `text-xs rounded border ... px-2 py-1`.

## 9. Tabs (Admin)

- Contenedor `flex gap-1 bg-gray-100 dark:bg-gray-800 p-1 rounded-lg w-fit`.
- Tab activo: `bg-white dark:bg-surface-dark text-brand-600 shadow-sm rounded-md`.
- Tab inactivo: `text-gray-600/400 hover:text-gray-900/dark:hover:text-white`.
- Cada tab: `flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors` con icono `size={16}`.

## 10. Diálogos / modales

- Overlay: `fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4`.
- Caja: tarjeta `bg-white dark:bg-surface-dark rounded-xl shadow-xl border w-full max-w-md p-6`.
- Cabecera: `flex items-center justify-between mb-4`, título `text-lg font-semibold` + botón cerrar `p-1 rounded hover:bg-gray-100/800 text-gray-500` con `X size={18}`.
- Cuerpo: `space-y-4` para campos.
- Mensajes inline: error `text-red-600 bg-red-50 dark:bg-red-950 px-3 py-2 rounded-lg`, éxito en green equivalente.
- Pie de acciones: `flex gap-3 pt-2` con botón cancelar (secundario) + botón guardar (primario), ambos `flex-1`.

## 11. Dropdowns genéricos (ExportButton, etc.)

- Trigger: botón secundario con icono + texto.
- Overlay de cierre: `fixed inset-0 z-30` transparente.
- Panel: `absolute right-0 mt-1 w-32 bg-white dark:bg-surface-dark border rounded-lg shadow-lg z-40 overflow-hidden`.
- Ítems: `w-full text-left px-4 py-2 text-sm hover:bg-gray-50/dark:hover:bg-muted-dark transition-colors`.

## 12. Panel de filtros (drawer lateral)

- Overlay `fixed inset-0 bg-black/30 z-40 lg:hidden`.
- Panel `fixed lg:static top-0 right-0 h-full w-72 bg-surface border-l z-50 overflow-y-auto p-4`.
- En `lg` se vuelve estático dentro del flujo (sin overlay).
- Cabecera `flex items-center justify-between mb-4` con título `text-sm font-semibold` y botón cerrar.
- Contenido `space-y-4`: cada filtro = label `text-xs` + control. Botón reset al final, ancho completo.

## 13. Paginación

- `flex flex-col sm:flex-row items-center justify-between gap-4 py-4`.
- Izquierda: contador "mostrando X–Y de Z" en `text-sm text-gray-500` con `<strong>` en los números.
- Derecha: botones anterior/siguiente `px-3 py-1.5 rounded-lg border text-sm font-medium` con `ChevronLeft/Right size={16}`, `disabled:opacity-40 disabled:cursor-not-allowed`, hover `bg-gray-50/dark:hover:bg-muted-dark`. Entre ambos, texto "Página X de N".
- Se oculta por completo si `totalPages <= 1`.

## 14. Gráficos (recharts)

Todos comparten el wrapper de tarjeta (`rounded-xl border p-4`, título `text-sm font-semibold mb-4`) y `ResponsiveContainer width="100%" height={280|300}`.

- **CartesianGrid**: `strokeDasharray="3 3" stroke="#374151" opacity={0.2}` (grid sutil).
- **Ejes**: `tick={{ fontSize: 12 }} stroke="#9CA3AF"`, `allowDecimals={false}`. Eje Y categórico con `width={80|100}` y `fontSize: 11`.
- **Tooltip** (estilo común): `backgroundColor: rgba(15,23,42,0.95)`, `border: 1px solid #374151`, `borderRadius: 8px`, `color: #F3F4F6` — tooltip oscuro flotante con brand invisible, coherente con el tema dark.
- **Serie principal**: `stroke="#f97316" strokeWidth={2} dot={false}`.
- **Serie secundaria** (financiero): `stroke="#fb923c" strokeWidth={2} strokeDasharray="5 5"`.
- **Barras horizontales**: `layout="vertical"`, `radius={[0,4,4,0]}` (esquinas redondeadas solo a la derecha), `Cell` por color.
- **Donut/Pie**: `innerRadius={60} outerRadius={100} paddingAngle={2}`, `Legend` a `fontSize: 12`.
- **Paleta de series** (array cíclico por índice): `['#f97316','#fb923c','#fdba74','#fed7aa','#ffedd5', ...]` — degradado del brand hacia tonos pastel, extendido con grises slate para series largas (`#94a3b8`, `#64748b`, `#475569`).
- Las páginas de Stats usan `p-6` y `text-lg font-semibold` en los títulos (densidad mayor que el dashboard).

## 15. Mapa (Leaflet)

- Contenedor tarjeta `rounded-xl border overflow-hidden`, mapa a `height: 600px`.
- Tiles OpenStreetMap estándar.
- `CircleMarker` por país: radio `Math.max(5, Math.min(40, total*2))` (tamaño proporcional acotado).
  - Con víctimas financieras: `color: #f97316`, `fillColor: #fb923c`, `fillOpacity: 0.6`.
  - Sin ellas: grises `#6b7280` / `#9ca3af`.
- Popup con `<div class="text-sm">`, país en `<strong>` y totales.

## 16. Espaciado y ritmo

No hay una escala custom; se sigue la de Tailwind de forma consistente:

- Separación vertical entre bloques de página: `space-y-4` (listados) o `space-y-6` (detalle/dashboard).
- Gap de grids: `gap-4` (estándar), `gap-6` (secciones grandes en Stats).
- Padding de página: `p-6` en `main`.
- Padding de tarjetas: `p-4` / `p-5` / `p-6` según densidad.
- Margins internos: `mb-1`, `mb-2`, `mb-4`, `mt-2`, `mt-3`, `mt-6` — sin valores intermedios raros.
- `gap` de iconos + texto: `gap-1` (apretado, badges), `gap-2` (inputs), `gap-3` (tarjetas/filas), `gap-4` (header).

## 17. Responsive

- Breakpoints de Tailwind por defecto (`sm 640`, `md 768`, `lg 1024`, `xl 1280`).
- Sidebar drawer < `lg`; fijo ≥ `lg`.
- Grids: 1 col base, escalonado a 2 en `sm`/`md`/`lg` y a 3–4 en `lg`/`xl` según contexto.
  - KPI: `1 → sm:2 → lg:4`.
  - Listados: `1 → md:2 → xl:3`.
  - Charts: `1 → lg:2`.
- Botones con texto: el label se oculta en móvil (`hidden sm:inline`) dejando solo el icono.
- Paginación: apilada en móvil (`flex-col`), horizontal en `sm+`.

## 18. Estados de carga y vacío

- **Spinner**: `w-8 h-8 border-4 border-brand-200 border-t-brand-500 rounded-full animate-spin`, centrado en `h-64`.
- **PageLoader** (Suspense): mismo spinner centrado.
- **Carga de texto**: `text-sm text-gray-500` "Cargando…".
- **Vacío**: `text-sm text-gray-500` sin resultados, sin ilustración.
- **Error**: `text-sm text-red-500` con enlace `underline` a reintentar; o banner `bg-red-50 dark:bg-red-950 px-3 py-2 rounded-lg`.
- **Éxito**: banner green equivalente.
- **Progreso en segundo plano**: banner blue con `Loader2 size={14} animate-spin`.

## 19. Iconografía

- Librería única: `lucide-react`. Stroke consistente (1.5 por defecto).
- Tamaños canónicos por contexto:
  - `12` — meta de pie de tarjeta.
  - `14` — dentro de chips/badges, menús desplegables.
  - `16` — inputs, botones, menús usuario, acciones de tabla.
  - `18` — ítems de sidebar, iconos de KPI, theme toggle.
  - `20` — botón hamburguesa/cerrar sidebar.
  - `32` — logo de login.
- Color de icono "decorativo/acentuado": `text-brand-500`. Icono "neutro/meta": `text-gray-400/500`.

## 20. Transiciones y microinteracciones

- `.transition-theme` (global): transición de `background-color, border-color, color, fill, stroke` con `cubic-bezier(0.4,0,0.2,1)` a `200ms`. Suaviza el cambio de tema en toda la app.
- `transition-colors` en hovers de botones, ítems de menú, enlaces.
- `transition-all` en tarjetas clicables (combina borde + sombra).
- Drawer del sidebar: `transform transition-transform duration-200`.
- `animate-spin` para spinners y `Loader2`.
- No hay animaciones de entrada de página más allá del fallback de Suspense; la sensación de "ágil" viene de transiciones cortas (200ms) y de lazy-loading por ruta.

## 21. Rutas y lazy-loading (patrón de navegación)

- Cada página se importa con `React.lazy(() => import(...))` y se envuelve en `<Suspense fallback={<PageLoader/>}>`.
- `QueryClient` con `staleTime: 2min`, `retry: 1`, `refetchOnWindowFocus: false` — la UI no repinta al cambiar de pestaña del navegador.
- Rutas protegidas: un wrapper redirige a `/login` si no hay sesión; muestra pantalla de carga mientras se verifica.
- Layout anidado: el `AppLayout` es la ruta padre con `<Outlet/>`; las páginas son hijas.

## 22. i18n (regla de oro de texto)

- **Ningún texto está hardcodeado** en componentes. Todo pasa por `useTranslation()` + claves (`t('nav.dashboard')`, etc.).
- Para replicar el sistema visual basta con el layout y los estilos; el contenido textual se mueve a `locales/{es,en}.json` con la misma estructura de claves anidadas (`nav`, `dashboard`, `victims`, `common`...).
- `common` agrupa verbos reutilizables: `filter`, `search`, `reset`, `close`, `export`, `csv`, `json`, `loading`, `error`, `retry`, `back`, `all`, `showing`, `of`, `results`, `page`, `previous`, `next`, `yes`, `no`.

## 23. Favicon y meta

- `<meta name="theme-color" content="#f97316">` — el color de la barra del navegador móvil es brand-500.
- `favicon.svg`: círculo `#f97316` con triángulo blanco + punto (referencia al escudo/alerta).
- `lang="es"` por defecto en el HTML.

## 24. Resumen de reglas de diseño para replicar

1. **Un solo acento**: brand-500 (`#f97316`). Todo lo destacado (foco, CTA, activo, logo, serie 1) es brand; lo demás es gris.
2. **Dual theme por clase**: `.dark` en `<html>`, tokens `surface`/`muted`, transición global de 200ms.
3. **Semántica con la paleta Tailwind estándar** (red/orange/yellow/green/blue), nunca usar naranja Tailwind para semántica (choca con la marca).
4. **Tarjeta = unidad base**: `rounded-xl border` sin sombra, sombra solo en hover de elementos clicables.
5. **Foco único**: `ring-2 ring-brand-500 border-transparent`.
6. **Tipografía binaria**: Inter para todo, JetBrains Mono solo para identificadores técnicos.
7. **Iconografía lucide con tamaños canónicos** por contexto (12/14/16/18/20/32).
8. **i18n obligatorio**: cero strings literales en componentes.
9. **Espaciado en escala Tailwind** (`4/5/6`, gaps `1/2/3/4`), sin valores arbitrarios.
10. **Lazy-loading por ruta + Suspense** para mantener el bundle inicial ligero.

---

*Generado a partir del análisis del frontend en `frontend/src/` (tokens, Tailwind config, layout, sidebar, header, cards, badges, charts, tablas, diálogos, theme store).*
