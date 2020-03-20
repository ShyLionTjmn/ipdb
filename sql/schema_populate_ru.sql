INSERT INTO atts(att_key,att_object,att_regex,att_name,att_comment,att_default,att_type, att_multiple, att_flags) VALUES
 ('autoreg_max_users', 'system', '^[0-9]+$', 'Макс. пользователей авторег.', 'Максимально допустимое количество пользователей в состоянии авторегистрации. Для возобновления авторегистрации нужно удалить или подтвердить имеющихся в этом состоянии.', '20', 'number', 0, 1)
,('router_groups', 'v4net', '^[a-zA-Z0-9_]{1,64}@[a-zA-Z0-9_\.]{1,64}$', 'Группы на маршрутизаторах', 'Атрибут для автозаполнения object-group на маршрутизаторах', 'public_services@all', 'text', 1, 1)
,('router_groups', 'v4ip', '^[a-zA-Z0-9_]{1,64}@[a-zA-Z0-9_\.]{1,64}$', 'Группы на маршрутизаторах', 'Атрибут для автозаполнения object-group на маршрутизаторах', 'public_services@all', 'text', 1, 1)
,('router_groups', 'v4oob', '^[a-zA-Z0-9_]{1,64}@[a-zA-Z0-9_\.]{1,64}$', 'Группы на маршрутизаторах', 'Атрибут для автозаполнения object-group на маршрутизаторах', 'public_services@all', 'text', 1, 1)
,('router_groups', 'v6net', '^[a-zA-Z0-9_]{1,64}@[a-zA-Z0-9_\.]{1,64}$', 'Группы на маршрутизаторах', 'Атрибут для автозаполнения object-group на маршрутизаторах', 'public_services@all', 'text', 1, 1)
,('router_groups', 'v6ip', '^[a-zA-Z0-9_]{1,64}@[a-zA-Z0-9_\.]{1,64}$', 'Группы на маршрутизаторах', 'Атрибут для автозаполнения object-group на маршрутизаторах', 'public_services@all', 'text', 1, 1)
,('router_groups', 'v6oob', '^[a-zA-Z0-9_]{1,64}@[a-zA-Z0-9_\.]{1,64}$', 'Группы на маршрутизаторах', 'Атрибут для автозаполнения object-group на маршрутизаторах', 'public_services@all', 'text', 1, 1)
;
