INSERT INTO atts(att_key,att_object,att_regex,att_name,att_comment,att_default,att_type, att_flags)
  VALUES ('autoreg_max_users', 'system', '^[0-9]+$', 'Макс. пользователей авторег.', 'Максимально допустимое количество пользователей в состоянии авторегистрации. Для возобновления авторегистрации нужно удалить или подтвердить имеющихся в этом состоянии.', '20', 'number', 1)
;
