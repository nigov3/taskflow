-- =====================================================================
-- TaskFlow: схема базы данных и правила доступа для Supabase
-- ---------------------------------------------------------------------
-- КАК ИСПОЛЬЗОВАТЬ (2 минуты, без программирования):
--   1. Зарегистрируйтесь бесплатно на https://supabase.com и создайте проект.
--   2. Откройте вкладку "SQL Editor" -> "New query".
--   3. Вставьте ВЕСЬ этот файл и нажмите "Run".
--   4. Скопируйте из index.html строки SUPABASE_URL / SUPABASE_KEY и впишите
--      их в настройки проекта не нужно — наоборот: возьмите Project URL и
--      anon key из Supabase (Settings -> API) и вставьте в index.html.
-- =====================================================================

-- 1. Таблица профилей пользователей (кто есть кто и какие у него права)
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  name text not null default 'Участник',
  role text not null default 'member' check (role in ('owner', 'editor', 'member')),
  created_at timestamptz not null default now()
);

-- 2. Общая таблица состояния приложения (списки задач и сотрудников)
create table if not exists public.app_state (
  id text primary key,               -- 'tf_tasks' или 'tf_members'
  value jsonb not null,
  updated_at timestamptz not null default now()
);

-- 3. Включаем Row Level Security: сервер сам решает, кому что разрешено
alter table public.profiles enable row level security;
alter table public.app_state enable row level security;

-- 4. Функция: текущий пользователь — владелец?
create or replace function public.is_owner()
returns boolean
language sql stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'owner'
  );
$$;

-- 5. ПРОФИЛИ -----------------------------------------------------------
-- Видеть списки профилей могут только вошедшие пользователи.
drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles
  for select to authenticated
  using (true);

-- Создать профиль можно только ДЛЯ СЕБЯ. Первый участник может стать
-- владельцем (если владельцев ещё нет), остальные — только сотрудниками.
drop policy if exists "profiles_insert_self" on public.profiles;
create policy "profiles_insert_self" on public.profiles
  for insert to authenticated
  with check (
    id = auth.uid()
    and (role = 'member' or not exists (select 1 from public.profiles where role = 'owner'))
  );

-- Обновлять профили может только владелец. При этом он НЕ может передать
-- владство случайно всем сразу и не может изменить собственный id.
drop policy if exists "profiles_update_owner" on public.profiles;
create policy "profiles_update_owner" on public.profiles
  for update to authenticated
  using (public.is_owner())
  with check (public.is_owner());

-- Удалять профили — только владельцу (кроме самого себя).
drop policy if exists "profiles_delete_owner" on public.profiles;
create policy "profiles_delete_owner" on public.profiles
  for delete to authenticated
  using (public.is_owner() and id <> auth.uid());

-- 6. СОСТОЯНИЕ ПРИЛОЖЕНИЯ (задачи и команда) --------------------------
-- Читать могут все вошедшие.
drop policy if exists "state_select" on public.app_state;
create policy "state_select" on public.app_state
  for select to authenticated
  using (true);

-- Писать (создавать/обновлять) могут только владелец и редакторы.
drop policy if exists "state_write" on public.app_state;
create policy "state_write" on public.app_state
  for insert to authenticated
  with check (exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('owner', 'editor')
  ));

drop policy if exists "state_update" on public.app_state;
create policy "state_update" on public.app_state
  for update to authenticated
  using (exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('owner', 'editor')
  ))
  with check (exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('owner', 'editor')
  ));

-- Удалять записи состояния — только владельцу.
drop policy if exists "state_delete" on public.app_state;
create policy "state_delete" on public.app_state
  for delete to authenticated
  using (public.is_owner());

-- 7. НАЗНАЧЕНИЕ ВЛАДЕЛЬЦА ----------------------------------------------
-- Первый зарегистрированный пользователь становится владельцем автоматически.
-- Выполните этот запрос ОДИН раз после первой регистрации, либо вручную
-- назначьте владельца SQL-командой:
--
--   update public.profiles set role = 'owner' where email_ниже;
--
-- Проще всего так (замените you@example.com на свой email):
--
--   update public.profiles
--   set role = 'owner'
--   where id = (select id from auth.users where email = 'you@example.com');
--
-- Дальше менять роли можно прямо из интерфейса TaskFlow (панель «Команда»).

-- 8. Реальное время: включаем публикацию изменений для подписок клиента
alter publication supabase_realtime add table public.app_state;
