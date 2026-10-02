create schema if not exists war;
revoke all on schema war from public, anon, authenticated;
grant usage on schema war to service_role;
create table if not exists war.identities(kind text not null check(kind in ('ip','device','mac')), id text not null, first_seen timestamptz not null, primary key(kind,id));
create table if not exists war.devices(device_id text primary key, mac_addresses text[] not null default '{}', last_seen timestamptz not null default now());
create table if not exists war.licenses(license_id text primary key, device_id text not null, expires_utc timestamptz not null, revoked boolean not null default false, last_seen timestamptz not null default now());
create table if not exists war.rate_limits(ip_hash text primary key, window_start timestamptz not null, hits integer not null);
alter table war.identities enable row level security;
alter table war.devices enable row level security;
alter table war.licenses enable row level security;
alter table war.rate_limits enable row level security;
grant select,insert,update on all tables in schema war to service_role;
create or replace function public.war_authorize(p_device text,p_ip_hash text,p_macs text[],p_license_id text default null,p_expires timestamptz default null)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare t timestamptz:=clock_timestamp(); started timestamptz; deadline timestamptz; n integer; blocked boolean; m text;
begin
 if p_device !~ '^[A-F0-9]{32}$' or p_ip_hash !~ '^[A-F0-9]{64}$' or cardinality(p_macs)>16 then raise exception 'Invalid identity'; end if;
 -- Short global transaction lock serializes overlapping IP/MAC/device registration.
 perform pg_advisory_xact_lock(84008400);
 insert into war.rate_limits values(p_ip_hash,date_trunc('minute',t),1)
 on conflict(ip_hash) do update set hits=case when war.rate_limits.window_start=excluded.window_start then war.rate_limits.hits+1 else 1 end, window_start=excluded.window_start returning hits into n;
 if n>60 then return jsonb_build_object('status',429,'error','Too many verification requests. Try again shortly.'); end if;
 select min(first_seen) into started from war.identities where (kind='ip' and id=p_ip_hash) or (kind='device' and id=p_device) or (kind='mac' and id=any(p_macs));
 started:=least(coalesce(started,t),t);deadline:=started+interval '7 days';
 insert into war.identities values('ip',p_ip_hash,started),('device',p_device,started) on conflict(kind,id) do update set first_seen=least(war.identities.first_seen,excluded.first_seen);
 foreach m in array p_macs loop
  if m !~ '^[A-F0-9]{12}$' then raise exception 'Invalid MAC'; end if;
  insert into war.identities values('mac',m,started) on conflict(kind,id) do update set first_seen=least(war.identities.first_seen,excluded.first_seen);
 end loop;
 insert into war.devices values(p_device,p_macs,t) on conflict(device_id) do update set mac_addresses=array(select distinct unnest(war.devices.mac_addresses||excluded.mac_addresses)),last_seen=t;
 if p_license_id is not null then
  if p_license_id !~ '^[a-zA-Z0-9_-]{1,64}$' or p_expires is null then raise exception 'Invalid subscription'; end if;
  insert into war.licenses(license_id,device_id,expires_utc,last_seen) values(p_license_id,p_device,p_expires,t)
  on conflict(license_id) do update set last_seen=t;
  select revoked into blocked from war.licenses where license_id=p_license_id;
  if blocked then return jsonb_build_object('status',403,'error','Subscription revoked. Enter a valid license.'); end if;
  if p_expires<=t then return jsonb_build_object('status',403,'error','Subscription expired. Enter a renewed license.'); end if;
  return jsonb_build_object('status',200,'kind','subscription','serverUtc',t,'expiresUtc',p_expires);
 end if;
 if deadline<=t then return jsonb_build_object('status',403,'error','The 7-day trial for this IP, PC or MAC has ended. A subscription is required.'); end if;
 return jsonb_build_object('status',200,'kind','trial','serverUtc',t,'expiresUtc',deadline);
end $$;
revoke all on function public.war_authorize(text,text,text[],text,timestamptz) from public,anon,authenticated;
grant execute on function public.war_authorize(text,text,text[],text,timestamptz) to service_role;
grant usage on schema vault to service_role;
grant select on vault.decrypted_secrets to service_role;
create or replace function public.war_signing_key() returns text language sql security invoker set search_path='' as $$
 select decrypted_secret from vault.decrypted_secrets where name='wifi_audio_robot_signing_key';
$$;
revoke all on function public.war_signing_key() from public,anon,authenticated;
grant execute on function public.war_signing_key() to service_role;
