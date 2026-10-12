# Pantalla de Login — Implementación de la interfaz

> Documento de referencia para replicar el diseño y el flujo de autenticación de la pantalla de login del FinSec TI Dashboard. Se describe el diseño visual, los espaciados, los estados, el flujo de datos y las decisiones de UX.

## 1. Ubicación y rol

- Componente: `frontend/src/pages/LoginPage.tsx` (export con nombre, sin lazy-loading).
- Ruta: `/login` — renderizada directamente en `App.tsx`, **fuera** del `AppLayout` (pantalla completa, sin sidebar ni header).
- Si ya hay sesión, `App.tsx` redirige a `/`; si no la hay tras un `ProtectedRoute`, redirige aquí.
- Es la única pantalla pública; no requiere auth previa.

## 2. Estructura visual general

Pantalla centrada sobre fondo de página, con una columna estrecha que contiene logo+titular arriba y la tarjeta-formulario debajo.

```
┌──────────────────────────────────────────┐
│  (fondo bg-gray-50 / dark:bg-gray-900)    │
│                                            │
│            ┌─────────────┐                │
│            │  [icono 64]  │  ← logo brand  │
│            └─────────────┘                │
│         FinSec TI Dashboard               │  ← h1
│      Threat Intelligence Dashboard        │  ← subtítulo
│                                            │
│      ┌──────────────────────────┐         │
│      │  [tarjeta formulario]    │         │
│      │  · Usuario o email       │         │
│      │  · Contraseña            │         │
│      │  [  Entrar  ]            │         │
│      └──────────────────────────┘         │
│                                            │
└──────────────────────────────────────────┘
```

### 2.1 Contenedor raíz

```html
<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
```

- `min-h-screen` ocupa toda la altura del viewport.
- `flex items-center justify-center` centra el contenido tanto vertical como horizontalmente.
- Fondo: `bg-gray-50` (light) / `bg-gray-900` (dark) — el mismo gris de página que el resto de la app, ligeramente distinto a `surface` para que la tarjeta flote.
- `px-4` da respiración horizontal en móvil y evita que la tarjeta toque los bordes.

### 2.2 Columna de contenido

```html
<div class="w-full max-w-sm">
```

- Ancho fluido hasta `max-w-sm` (24rem = 384px). Es una columna deliberadamente estrecha: el login es un formulario compacto, no una página ancha.
- Todo el contenido (logo + titular + formulario) vive dentro de esta columna.

### 2.3 Cabecera de marca

```html
<div class="text-center mb-8">
  <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-500 mb-4">
    <ShieldAlert size={32} class="text-white" />
  </div>
  <h1 class="text-2xl font-bold text-gray-900 dark:text-white">FinSec TI Dashboard</h1>
  <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Threat Intelligence Dashboard</p>
</div>
```

- **Logo**: contenedor cuadrado `w-16 h-16` (64px), `rounded-2xl` (esquinas más redondeadas que el resto de la app, que usa `rounded-lg`/`rounded-xl`), fondo `bg-brand-500` (naranja marca). Icono `ShieldAlert` a `size={32}` en blanco. Es la versión "grande" del logo del sidebar (que es `w-8 h-8 rounded-lg`).
- **Título** (`h1`): `text-2xl font-bold` en color primario. Es el único `text-2xl` de la pantalla.
- **Subtítulo** (`p`): `text-sm text-gray-500` con `mt-1`. Texto descriptivo en inglés, función puramente informativa.
- Separación con el formulario: `mb-8` (2rem) — el bloque de marca está claramente diferenciado de la tarjeta.
- Todo el bloque está `text-center`.

### 2.4 Tarjeta-formulario

```html
<form class="bg-white dark:bg-surface-dark rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6 space-y-4">
```

| Propiedad | Valor | Nota |
|---|---|---|
| Fondo | `bg-white` / `dark:bg-surface-dark` | Superficie principal |
| Esquinas | `rounded-xl` | 0.75rem, igual que las tarjetas de la app |
| Sombra | `shadow-sm` | **Único lugar** de toda la app que usa sombra por defecto; las demás tarjetas solo la muestran en hover. Le da protagonismo al login. |
| Borde | `border border-gray-200 dark:border-gray-700` | Igual que el resto de tarjetas |
| Padding | `p-6` | Densidad alta (formulario corto) |
| Layout interno | `space-y-4` | Separación vertical uniforme entre campos |

El contenido del formulario, de arriba a abajo:
1. Campo "Usuario o email"
2. Campo "Contraseña"
3. Mensaje de error (condicional)
4. Botón "Entrar"

## 3. Campos de formulario

### 3.1 Label

```html
<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
```

- `text-sm font-medium` — igual que en todos los formularios de la app.
- Color `gray-700`/`gray-300` (texto de etiqueta, no primario).
- `mb-1` separa label de input (0.25rem) — pegado al campo, no flotante.

### 3.2 Input

```html
<input
  class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600
         bg-white dark:bg-gray-800 text-gray-900 dark:text-white
         focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none"
/>
```

| Propiedad | Valor |
|---|---|
| Ancho | `w-full` |
| Padding | `px-3 py-2` (0.75rem / 0.5rem) |
| Esquinas | `rounded-lg` (0.5rem) |
| Borde | `border-gray-300` / `dark:border-gray-600` |
| Fondo | `bg-white` / `dark:bg-gray-800` (no `surface-dark` — se diferencia del contenedor) |
| Texto | `text-gray-900 dark:text-white` |
| Foco | `focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none` |
| Placeholder | `admin` (usuario) / `••••••••` (contraseña) |

El foco es el mismo de toda la app: anillo brand-500 de 2px y border transparente. Es el único foco visual y siempre es naranja.

### 3.3 Diferencias entre los dos campos

| Aspecto | Usuario | Contraseña |
|---|---|---|
| `type` | `text` | `password` |
| `autoFocus` | sí (campo inicial con foco al cargar) | no |
| Placeholder | `admin` | `••••••••` |
| Label | "Usuario o email" | "Contraseña" |

No hay icono dentro del input (a diferencia del `SearchInput` de la app, que sí lleva icono lateral). El login mantiene los inputs desnudos para minimizar distracción.

## 4. Mensaje de error

```html
<div class="text-sm text-red-500 bg-red-50 dark:bg-red-900/20 px-3 py-2 rounded-lg">
  {error}
</div>
```

- Aparece solo si `error` no es cadena vacía (renderizado condicional).
- Color texto `text-red-500` (ligeramente más vivo que el `text-red-600` de otros formularios; el login usa red-500).
- Fondo `bg-red-50` / `dark:bg-red-900/20` (con opacidad 20% en dark, más sutil que el `red-950` del modal de cambio de contraseña).
- `px-3 py-2 rounded-lg` — caja con esquinas redondeadas, mismo radio que los inputs.
- Se renderiza entre la contraseña y el botón, empujando el botón hacia abajo.
- Mensajes posibles:
  - `"Todos los campos son obligatorios"` (validación local, antes de llamar a la API).
  - `"Credenciales inválidas"` (cualquier fallo de la API, sin distinción de causa).

No hay estado de éxito en el login: tras autenticar, se navega a `/`.

## 5. Botón de envío

```html
<button
  type="submit"
  disabled={loading}
  class="w-full py-2.5 px-4 bg-brand-500 hover:bg-brand-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
>
  {loading ? 'Entrando...' : 'Entrar'}
</button>
```

| Propiedad | Valor | Nota |
|---|---|---|
| Ancho | `w-full` | Ocupa todo el formulario — es la única acción |
| Padding | `py-2.5 px-4` | Ligeramente más alto que un botón normal (`py-2`) para ser cómodo táctil |
| Color | `bg-brand-500 hover:bg-brand-600` | Botón primario estándar de la app |
| Texto | `text-white font-medium` | |
| Esquinas | `rounded-lg` | |
| Transición | `transition-colors` | |
| Disabled | `disabled:opacity-50 disabled:cursor-not-allowed` | Mismo patrón de toda la app |
| Label dinámico | `"Entrar"` → `"Entrando..."` | Cambia durante el loading |

El botón es `type="submit"`, por lo que disparar Enter en cualquier input envía el formulario.

## 6. Estados y flujo de UX

### 6.1 Estado inicial

- `username = ""`, `password = ""`, `error = ""`, `loading = false`.
- El campo usuario tiene `autoFocus`, así el cursor aparece ahí al cargar.
- El botón muestra "Entrar" y está habilitado (no se deshabilita por campos vacíos; la validación es en submit).

### 6.1 Envío (submit)

1. `e.preventDefault()` — no recarga la página.
2. Se limpia `error`.
3. Validación local: si `username` o `password` están vacíos tras `trim()`, se muestra `"Todos los campos son obligatorios"` y **no** se llama a la API.
4. `setLoading(true)` → el botón pasa a `"Entrando..."` y se deshabilita (`disabled:opacity-50`).
5. Se llama a `login({ username: username.trim(), password })`. El username se trima; la contraseña no.
6. Éxito: `setAuth(user, token)` guarda en `authStore` y `localStorage`, luego `navigate('/')`.
7. Fallo (cualquier excepción): se muestra `"Credenciales inválidas"`. El `finally` siempre pone `loading = false`.

### 6.3 Estado de carga

- El botón muestra `"Entrando..."` y `disabled:opacity-50 disabled:cursor-not-allowed`.
- **No** hay spinner en el login (el resto de la app usa `animate-spin`, pero aquí el botón de texto es suficiente feedback).
- Los inputs siguen editables durante el envío (no se bloquean).

### 6.4 Estado de error

- El banner rojo aparece entre la contraseña y el botón.
- No se distingue entre "usuario no existe", "contraseña incorrecta" o "servidor caído": todo es `"Credenciales inválidas"`. Es una decisión de seguridad (no filtrar qué campo falló).
- El error persiste hasta el próximo submit (que lo limpia al inicio).

### 6.5 Tras éxito

- Redirección inmediata a `/` (dashboard). No hay pantalla intermedia ni toast de "bienvenida".

## 7. Flujo de datos (auth)

El login es el punto de entrada al sistema de autenticación. La cadena es:

```
LoginPage → useAuth().login() → api/auth.login() → client.post('/auth/login')
                                                              │
                                          ┌───────────────────┘
                                          ▼
                                   LoginResponse { token, user, expires_in }
                                          │
                          authStore.setAuth(user, token)
                                          │
                          localStorage.setItem('session_token', token)
                          authStore → { isAuthenticated: true, isLoading: false }
                                          │
                                    navigate('/')
```

### 7.1 Cliente HTTP (`api/client.ts`)

- `axios.create({ baseURL: '/api', withCredentials: true })`.
- Request interceptor: añade `Authorization: Bearer <token>` si existe `localStorage.session_token`.
- Response interceptor: ante un 401, elimina `session_token` de `localStorage` (sesión caducada).

### 7.2 API de auth (`api/auth.ts`)

- `login(data)` → `POST /auth/login` con `{ username, password }`.
- `getMe()` → `GET /auth/me` (usa el guard de `App.tsx` para restaurar sesión al recargar).
- `logout()` → `POST /auth/logout`.
- `changePassword(data)` → `POST /auth/change-password` (no se usa en el login, pero es parte del flujo post-login si `must_change_password` es true).

### 7.3 Hook `useAuth`

- `login(data)`: llama a la API, en éxito hace `setAuth(user, token)`; en fallo hace `setLoading(false)` y relanza el error (para que el `catch` del `LoginPage` lo atrape).
- `fetchMe()`: usado por `App.tsx` al montar la app si hay `token` en `localStorage` pero no hay `user` en memoria. Restaura la sesión llamando a `/auth/me`.

### 7.4 Store `authStore` (Zustand)

- Estado inicial: `token = localStorage.getItem('session_token')` (persistencia manual, no `persist` middleware).
- `setAuth(user, token)`: escribe `localStorage`, pone `isAuthenticated: true`, `isLoading: false`.
- `clearAuth()`: elimina `localStorage`, pone todo a null/false.
- `isLoading` arranca en `true` para que `ProtectedRoute` muestre "Cargando..." hasta saber si hay sesión.

### 7.5 Tipos (`types/user.ts`)

```ts
interface User {
  id: number
  username: string
  email: string
  display_name: string | null
  role: 'admin' | 'user'
  locale: string
  theme: string
  must_change_password: boolean
  last_login_at: string | null
  created_at: string
}

interface LoginRequest  { username: string; password: string }
interface LoginResponse { token: string; user: User; expires_in: number }
```

El `role` determina acceso al `AdminPage`; `must_change_password` activa el banner de cambio de contraseña en el `AppHeader` tras el login.

## 8. Comportamiento con tema (dark mode)

- El login respeta el theme store como el resto de la app.
- Al ser una pantalla fuera del `AppLayout`, el theme toggle del header no está visible aquí. El tema se aplica según lo que haya en `localStorage.theme` (o `auto` → `prefers-color-scheme`).
- La transición de tema (`.transition-theme`, 200ms) afecta al fondo y a la tarjeta si se cambia de tema estando en el login (caso raro pero posible vía devtools).

## 9. Accesibilidad y teclado

- `autoFocus` en el campo usuario — foco inicial lógico.
- El botón es `type="submit"`, así Enter en cualquier input envía.
- `outline-none` en inputs combinado con `focus:ring-2 ring-brand-500` — el foco es visible (anillo naranja), no se pierde el indicador.
- Los labels son `block` y se asocian implícitamente por precedencia (no usan `htmlFor`/`id` en la implementación actual; a replicar con `htmlFor` + `id` si se quiere accesibilidad estricta).
- El botón deshabilitado usa `cursor-not-allowed` para señalizar el estado.

## 10. Responsive

- El contenedor raíz `px-4` evita que la tarjeta toque los bordes en móvil.
- `max-w-sm` (384px) hace que en escritorio el formulario quede centrado y compacto.
- No hay breakpoints intermedios: el login es una pantalla simple que no necesita grid ni reordenamiento.
- En pantallas muy estrechas, la tarjeta ocupa casi todo el ancho (menos 2×`px-4`).

## 11. Espaciado resumido

| Elemento | Clase | Valor |
|---|---|---|
| Padding horizontal raíz | `px-4` | 1rem |
| Separación logo → título | `mb-4` (logo) | 1rem |
| Separación título → subtítulo | `mt-1` | 0.25rem |
| Separación bloque marca → tarjeta | `mb-8` | 2rem |
| Padding interno tarjeta | `p-6` | 1.5rem |
| Separación entre campos | `space-y-4` | 1rem |
| Separación label → input | `mb-1` | 0.25rem |
| Padding input | `px-3 py-2` | 0.75rem / 0.5rem |
| Padding botón | `py-2.5 px-4` | 0.625rem / 1rem |
| Ancho máximo columna | `max-w-sm` | 24rem (384px) |

## 12. HTML del body (herencia)

El `<body>` de `index.html` define los colores base de toda la app:

```html
<body class="bg-surface-light text-slate-900 dark:bg-surface-dark dark:text-slate-100">
```

Sin embargo, el login **no** usa estos tokens del body: su contenedor raíz impone `bg-gray-50 dark:bg-gray-900`, que pisa el fondo del body. Esto es coherente con el resto de la app (el `AppLayout` también sobreescribe el fondo a `bg-gray-50 dark:bg-gray-900`). El body usa `surface-light`/`surface-dark` como fallback por si parpadea antes del montaje de React.

## 13. Paleta aplicada al login

| Elemento | Claro | Oscuro |
|---|---|---|
| Fondo página | `bg-gray-50` (#f9fafb) | `bg-gray-900` (#111827) |
| Tarjeta | `bg-white` | `bg-surface-dark` (#0f172a) |
| Logo | `bg-brand-500` (#f97316) | `bg-brand-500` (#f97316) |
| Icono logo | `text-white` | `text-white` |
| Título h1 | `text-gray-900` (#111827) | `text-white` |
| Subtítulo | `text-gray-500` (#6b7280) | `text-gray-400` (#9ca3af) |
| Label | `text-gray-700` (#374151) | `text-gray-300` (#d1d5db) |
| Input fondo | `bg-white` | `bg-gray-800` (#1f2937) |
| Input borde | `border-gray-300` (#d1d5db) | `border-gray-600` (#4b5563) |
| Input texto | `text-gray-900` | `text-white` |
| Input foco | `ring-brand-500` (#f97316) | `ring-brand-500` |
| Error texto | `text-red-500` (#ef4444) | `text-red-500` |
| Error fondo | `bg-red-50` (#fef2f2) | `bg-red-900/20` (rgba(127,29,29,0.2)) |
| Botón | `bg-brand-500` / `hover:bg-brand-600` | idem |
| Botón texto | `text-white` | `text-white` |
| Sombra tarjeta | `shadow-sm` | `shadow-sm` |

## 14. Diferencias con el resto de la app

Para no duplicar el documento general, aquí se listan las decisiones que el login **toma de forma distinta** al resto:

| Aspecto | App general | Login |
|---|---|---|
| Sombra de tarjeta | solo en hover (`hover:shadow-md`) | `shadow-sm` por defecto (protagonismo) |
| Esquinas del logo | `rounded-lg` (sidebar, w-8) | `rounded-2xl` (login, w-16) |
| Color de error texto | `text-red-600` | `text-red-500` |
| Color de error fondo dark | `bg-red-950` | `bg-red-900/20` (más sutil) |
| Botón padding | `py-2` | `py-2.5` (más alto) |
| Spinner en loading | `animate-spin` en botones de acción | sin spinner, solo cambio de texto |
| i18n | `useTranslation` en todos lados | **strings hardcodeados** en el login (ver nota) |
| Layout | dentro de `AppLayout` (sidebar + header) | pantalla completa aislada |

> **Nota sobre i18n:** la implementación actual del `LoginPage` tiene los textos hardcodeados en español ("Usuario o email", "Contraseña", "Entrar", mensajes de error), a diferencia del resto de la app que usa `react-i18next`. Esto parece una inconsistencia respecto a la regla del `AGENTS.md` ("i18n: react-i18next, NUNCA hardcodeados"). Al replicar, se recomienda mover estos textos a `locales/{es,en}.json` bajo una clave `login.*` (que ya existe en `es.json`: `login.title`, `login.username`, `login.password`, `login.submit`, `login.error`, `login.required`).

## 15. Esqueleto JSX para replicar

```tsx
<div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
  <div className="w-full max-w-sm">
    {/* Marca */}
    <div className="text-center mb-8">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-500 mb-4">
        <ShieldAlert size={32} className="text-white" />
      </div>
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{t('login.title_app')}</h1>
      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{t('login.subtitle')}</p>
    </div>

    {/* Formulario */}
    <form onSubmit={handleSubmit} className="bg-white dark:bg-surface-dark rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6 space-y-4">
      {/* Usuario */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('login.username')}</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none"
          autoFocus
        />
      </div>

      {/* Contraseña */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('login.password')}</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none"
        />
      </div>

      {/* Error */}
      {error && (
        <div className="text-sm text-red-500 bg-red-50 dark:bg-red-900/20 px-3 py-2 rounded-lg">{error}</div>
      )}

      {/* Botón */}
      <button
        type="submit"
        disabled={loading}
        className="w-full py-2.5 px-4 bg-brand-500 hover:bg-brand-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? t('login.submitting') : t('login.submit')}
      </button>
    </form>
  </div>
</div>
```

## 16. Claves i18n sugeridas (consistencia con es.json)

El archivo `es.json` ya define estas claves; el login actual no las usa pero deberían aplicarse al replicar:

```json
{
  "login": {
    "title": "Iniciar sesión",
    "title_app": "FinSec TI Dashboard",
    "subtitle": "Threat Intelligence Dashboard",
    "username": "Usuario o email",
    "password": "Contraseña",
    "submit": "Entrar",
    "submitting": "Entrando...",
    "error": "Credenciales inválidas",
    "required": "Todos los campos son obligatorios"
  }
}
```

---

*Generado a partir del análisis de `frontend/src/pages/LoginPage.tsx`, `hooks/useAuth.ts`, `api/auth.ts`, `api/client.ts`, `store/authStore.ts`, `types/user.ts` e `index.html`.*
