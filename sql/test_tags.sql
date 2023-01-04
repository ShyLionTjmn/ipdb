SET FOREIGN_KEY_CHECKS=0;
SET sql_safe_updates=0;

DELETE FROM tags;

SET @F_ALLOW_LEAFS=1;
SET @F_DENY_SELECT=2;

SET @name='root1';
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_api_name=@name, tag_sort=@sort, tag_parent_id=0, tag_fk_tag_id=NULL, ts=UNIX_TIMESTAMP()
  , tag_flags=@F_ALLOW_LEAFS|@F_DENY_SELECT
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);
SET @ROOT1 = LAST_INSERT_ID();


SET @name='root1_leaf1';
SET @root=@ROOT1;
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_sort=@sort, tag_parent_id=@root, tag_fk_tag_id=@root, ts=UNIX_TIMESTAMP()
  , tag_flags=@F_ALLOW_LEAFS|@F_DENY_SELECT
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);
SET @LEAF1 = LAST_INSERT_ID();

SET @name='root1_leaf1_leaf11';
SET @root=@LEAF1;
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_sort=@sort, tag_parent_id=@root, tag_fk_tag_id=@root, ts=UNIX_TIMESTAMP()
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);

SET @name='root1_leaf1_leaf12';
SET @root=@LEAF1;
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_sort=@sort, tag_parent_id=@root, tag_fk_tag_id=@root, ts=UNIX_TIMESTAMP()
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);



SET @name='root1_leaf2';
SET @root=@ROOT1;
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_sort=@sort, tag_parent_id=@root, tag_fk_tag_id=@root, ts=UNIX_TIMESTAMP()
  , tag_flags=@F_ALLOW_LEAFS|@F_DENY_SELECT
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);

SET @name='root2';
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_api_name=@name, tag_sort=@sort, tag_parent_id=0, tag_fk_tag_id=NULL, ts=UNIX_TIMESTAMP()
  , tag_flags=@F_ALLOW_LEAFS|@F_DENY_SELECT
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);
SET @ROOT2 = LAST_INSERT_ID();

SET @name='root3';
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_api_name=@name, tag_sort=@sort, tag_parent_id=0, tag_fk_tag_id=NULL, ts=UNIX_TIMESTAMP()
  , tag_flags=@F_ALLOW_LEAFS|@F_DENY_SELECT
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);
SET @ROOT3 = LAST_INSERT_ID();

SET @name='root3_leaf1';
SET @root=@ROOT3;
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_sort=@sort, tag_parent_id=@root, tag_fk_tag_id=@root, ts=UNIX_TIMESTAMP()
  , tag_flags=@F_ALLOW_LEAFS|@F_DENY_SELECT
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);
SET @LEAF1 = LAST_INSERT_ID();

SET @name='root3_leaf1_leaf11';
SET @root=@LEAF1;
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_sort=@sort, tag_parent_id=@root, tag_fk_tag_id=@root, ts=UNIX_TIMESTAMP()
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);

SET @name='root3_leaf1_leaf12';
SET @root=@LEAF1;
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_sort=@sort, tag_parent_id=@root, tag_fk_tag_id=@root, ts=UNIX_TIMESTAMP()
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);

SET @name='root3_leaf2';
SET @root=@ROOT3;
SET @sort=CEIL(RAND()*100);
INSERT INTO tags SET
  tag_name=@name, tag_sort=@sort, tag_parent_id=@root, tag_fk_tag_id=@root, ts=UNIX_TIMESTAMP()
  , tag_flags=@F_ALLOW_LEAFS|@F_DENY_SELECT
  , fk_u_id=(SELECT u_id FROM us ORDER BY RAND() LIMIT 1);

INSERT INTO tgrs(tgr_fk_tag_id, tgr_fk_g_id, tgr_rmask, ts)
  SELECT tag_id, 2, 4, UNIX_TIMESTAMP() FROM tags WHERE tag_fk_tag_id IS NULL;

UPDATE tgrs SET tgr_rmask = 4+8 WHERE tgr_fk_tag_id = @ROOT1;
