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
  -- pending: доступ ещё не выдан (приложение закрыто «на замок»);
  -- member/editor/owner — обычные рабочие роли.
  role text not null default 'pending' check (role in ('owner', 'editor', 'member', 'pending')),
  created_at timestamptz not null default now()
);

-- Колонка email (для отображения в панели доступа) + триггер, который
-- заполняет её автоматически при регистрации нового аккаунта.
alter table public.profiles add column if not exists email text;

create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, name, email, role)
  values (
    new.id,
    coalesce(nullif(new.raw_user_meta_data ->> 'name', ''), split_part(new.email, '@', 1)),
    new.email,
    -- Первый человек становится владельцем сразу на сервере (в обход RLS),
    -- все остальные попадают в очередь «ожидает доступа» (pending).
    case when not exists (select 1 from public.profiles where role = 'owner')
         then 'owner' else 'pending' end
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 2. Общая таблица состояния приложения (списки задач и сотрудников)
create table if not exists public.app_state (
  id text primary key,               -- 'tf_tasks' или 'tf_members'
  value jsonb not null,
  updated_at timestamptz not null default now()
);

-- 3. Включаем Row Level Security: сервер сам решает, кому что разрешено
alter table public.profiles enable row level security;
alter table public.app_state enable row level security;

-- 4. Функции проверки прав (используются в политиках ниже)
create or replace function public.is_owner()
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'owner'
  );
$$;

-- Пользователь получил доступ (владелец / редактор / сотрудник)?
-- Профиль ещё не создан или висит в статусе pending — доступа нет.
create or replace function public.is_approved()
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('owner', 'editor', 'member')
  );
$$;

-- 5. ПРОФИЛИ -----------------------------------------------------------
-- Свой профиль человек видеть может всегда (в т.ч. в статусе pending —
-- иначе приложение не поймёт, что он «в очереди»). Чужие профили видят
-- только одобренные пользователи (нужно владельцу для панели доступа).
drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.is_owner());

-- Самостоятельное создание профиля запрещено: его создаёт серверный
-- триггер при регистрации (см. пункт 1). Обмануть роль нельзя.
drop policy if exists "profiles_insert_self" on public.profiles;
create policy "profiles_insert_self" on public.profiles
  for insert to authenticated
  with check (false);

-- Обновлять профили может только владелец. Он НЕ может понизить собственную
-- роль (чтобы случайно не запереть себя вне приложения).
drop policy if exists "profiles_update_owner" on public.profiles;
create policy "profiles_update_owner" on public.profiles
  for update to authenticated
  using (public.is_owner() and id <> auth.uid())
  with check (public.is_owner());

-- Удалять профили — только владельцу (кроме самого себя).
drop policy if exists "profiles_delete_owner" on public.profiles;
create policy "profiles_delete_owner" on public.profiles
  for delete to authenticated
  using (public.is_owner() and id <> auth.uid());

-- 6. СОСТОЯНИЕ ПРИЛОЖЕНИЯ (задачи и команда) --------------------------
-- Читать могут ТОЛЬКО одобренные пользователи. Незарегистрированные и
-- те, кому доступ ещё не выдан (pending), получают пустой ответ — данные
-- не покидают сервер.
drop policy if exists "state_select" on public.app_state;
create policy "state_select" on public.app_state
  for select to authenticated
  using (public.is_approved());

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

-- 7. ВЛАДЕЛЕЦ -----------------------------------------------------------
-- Владелец назначается автоматически: первый зарегистрированный человек
-- становится им на уровне серверного триггера (пункт 1). Никто больше не
-- сможет стать владельцем через саморегистрацию — только текущий владелец
-- повысит человека ролью «Владелец» в панели «Доступ к приложению».
--
-- Если хотите назначить владельца вручную (например, регистратор-бот уже
-- создал аккаунт раньше вас), выполните один раз:
--
--   update public.profiles
--   set role = 'owner'
--   where id = (select id from auth.users where email = 'you@example.com');

-- 8. Реальное время: включаем публикацию изменений для подписок клиента
alter publication supabase_realtime add table public.app_state;

-- 9. ВАЖНО: отключите «Confirm email» в Supabase (Authentication -> Providers
--    -> Email), иначе новый аккаунт появится только после подтверждения почты,
--    а одобрить его владелец сможет только после этого входа.
